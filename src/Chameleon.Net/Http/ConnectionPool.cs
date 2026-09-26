using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Chameleon.Net.Http.Http1;
using Chameleon.Net.Http.Http2;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Microsoft.Extensions.Logging;

namespace Chameleon.Net.Http;

/// <summary>Per origin: one shared HTTP/2 connection, or a stack of idle HTTP/1.1 connections. ALPN decides which one a new connection becomes.</summary>
internal sealed class ConnectionPool : IDisposable
{
    /// <summary>OkHttp's ConnectionPool defaults. Servers usually drop idle connections sooner (60–75 s); a request that meets such a
    /// connection is replayed on a fresh one, as OkHttp does.</summary>
    private static readonly TimeSpan KeepAlive = TimeSpan.FromMinutes(5);

    private const int MaxIdleConnections = 5;

    private static readonly TimeSpan CleanupInterval = TimeSpan.FromSeconds(10);

    private readonly Lock _idleLock = new();
    private readonly List<Http1Connection> _idleHttp1 = [];
    private readonly List<Http2Connection> _retiredHttp2 = [];
    private readonly ConcurrentDictionary<Origin, Http2Connection> _http2 = new();
    private readonly Timer _cleanup;
    private readonly IProfileSelector _profileSelector;
    private readonly ITlsConnectionFactory _tlsConnectionFactory;
    private readonly ProxyRouting _routing;
    private readonly TimeSpan _connectTimeout;
    private readonly ILogger _logger;
    private volatile bool _disposed;

    public ConnectionPool(IProfileSelector profileSelector, ITlsConnectionFactory tlsConnectionFactory, ProxyRouting routing, TimeSpan connectTimeout, ILogger logger)
    {
        _profileSelector = profileSelector;
        _tlsConnectionFactory = tlsConnectionFactory;
        _routing = routing;
        _connectTimeout = connectTimeout;
        _logger = logger;
        _cleanup = new Timer(static state => ((ConnectionPool)state!).Cleanup(), this, CleanupInterval, CleanupInterval);
    }

    /// <param name="http2PriorKnowledge">Cleartext only: speak HTTP/2 without negotiation (h2c).</param>
    public async Task<IHttpConnection> RentAsync(Origin origin, bool http2PriorKnowledge, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var secure = HttpUris.IsSecure(origin.Scheme);

        if ((secure || http2PriorKnowledge) && _http2.TryGetValue(origin, out var shared))
        {
            if (shared.IsReusable)
            {
                return shared;
            }

            // Going away: in-flight streams finish on their own, new ones go elsewhere; cleanup closes it once idle.
            _http2.TryRemove(new KeyValuePair<Origin, Http2Connection>(origin, shared));
            lock (_idleLock)
            {
                _retiredHttp2.Add(shared);
            }
        }

        if (!http2PriorKnowledge && TakeIdle(origin) is { } idle)
        {
            return idle;
        }

        return await ConnectAsync(origin, _profileSelector.SelectForConnection(origin), secure, http2PriorKnowledge, cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        _disposed = true;
        _cleanup.Dispose();

        List<IDisposable> connections;
        lock (_idleLock)
        {
            connections = [.. _idleHttp1, .. _retiredHttp2, .. _http2.Values];
            _idleHttp1.Clear();
            _retiredHttp2.Clear();
            _http2.Clear();
        }

        foreach (var connection in connections)
        {
            connection.Dispose();
        }
    }

    /// <summary>Most recently used first, like OkHttp.</summary>
    private Http1Connection? TakeIdle(Origin origin)
    {
        List<Http1Connection> broken = [];
        Http1Connection? found = null;
        lock (_idleLock)
        {
            for (var i = _idleHttp1.Count - 1; i >= 0 && found is null; i--)
            {
                var candidate = _idleHttp1[i];
                if (candidate.Origin != origin)
                {
                    continue;
                }

                _idleHttp1.RemoveAt(i);
                if (candidate.IsReusable)
                {
                    found = candidate;
                }
                else
                {
                    broken.Add(candidate);
                }
            }
        }

        broken.ForEach(static connection => connection.Dispose());
        found?.MarkReused();
        return found;
    }

    private void Release(Http1Connection connection)
    {
        if (_disposed)
        {
            connection.Dispose();
            return;
        }

        connection.MarkIdle();
        lock (_idleLock)
        {
            _idleHttp1.Add(connection);
        }

        Cleanup();
    }

    /// <summary>OkHttp's <c>RealConnectionPool.cleanup</c>: close connections idle for the keep-alive duration, then the longest-idle ones
    /// beyond the idle limit. Evicted sockets are closed quietly, without GOAWAY.</summary>
    private void Cleanup()
    {
        var evicted = new List<IDisposable>();
        lock (_idleLock)
        {
            evicted.AddRange(_idleHttp1.Where(static c => !c.IsReusable || c.IdleTime >= KeepAlive));
            _idleHttp1.RemoveAll(evicted.Contains);

            foreach (var retired in _retiredHttp2.Where(static c => c.IdleTime is not null || c.IsClosed).ToList())
            {
                _retiredHttp2.Remove(retired);
                evicted.Add(retired);
            }

            foreach (var (origin, connection) in _http2)
            {
                if (connection.IsClosed || connection.TryRetire(KeepAlive))
                {
                    _http2.TryRemove(new KeyValuePair<Origin, Http2Connection>(origin, connection));
                    evicted.Add(connection);
                }
            }

            var idle = _idleHttp1.Select(static c => (Connection: (IHttpConnection)c, Idle: c.IdleTime))
                .Concat(_http2.Values.Where(static c => c.IdleTime is not null).Select(static c => (Connection: (IHttpConnection)c, Idle: c.IdleTime!.Value)))
                .OrderByDescending(static entry => entry.Idle)
                .ToList();
            for (var excess = idle.Count - MaxIdleConnections; excess > 0 && idle.Count > 0; idle.RemoveAt(0))
            {
                switch (idle[0].Connection)
                {
                    case Http1Connection http1:
                        _idleHttp1.Remove(http1);
                        evicted.Add(http1);
                        excess--;
                        break;
                    case Http2Connection http2 when http2.TryRetire(TimeSpan.Zero):
                        _http2.TryRemove(new KeyValuePair<Origin, Http2Connection>(http2.Origin, http2));
                        evicted.Add(http2);
                        excess--;
                        break;
                }
            }
        }

        foreach (var connection in evicted)
        {
            connection.Dispose();
        }
    }

    private async Task<IHttpConnection> ConnectAsync(Origin origin, ClientProfile profile, bool secure, bool http2PriorKnowledge, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_connectTimeout);

        var target = new UriBuilder(origin.Scheme, origin.Host, origin.Port).Uri;
        var forwardProxy = secure || http2PriorKnowledge ? null : _routing.ForwardProxyFor(target);
        var transport = _routing.For(target, profile);
        Stream? stream = null;
        try
        {
            string? protocol;
            var resumed = false;
            if (secure)
            {
                var tls = await _tlsConnectionFactory.ConnectAsync(transport, origin.Host, origin.Port, profile.Tls, timeout.Token).ConfigureAwait(false);
                stream = tls.Stream;
                protocol = tls.NegotiatedProtocol;
                resumed = tls.SessionResumed;
            }
            else
            {
                stream = forwardProxy is null
                    ? await transport.ConnectAsync(new DnsEndPoint(origin.Host, origin.Port), timeout.Token).ConfigureAwait(false)
                    : await forwardProxy.Transport.ConnectAsync(forwardProxy.Endpoint, timeout.Token).ConfigureAwait(false);
                protocol = http2PriorKnowledge ? "h2" : null;
            }

            IHttpConnection connection = protocol switch
            {
                "h2" => Share(origin, await Http2Connection.OpenAsync(origin, profile, stream, _logger, timeout.Token).ConfigureAwait(false)),
                null or "http/1.1" => new Http1Connection(origin, profile, stream, Release, forwardProxy),
                _ => throw new HttpRequestException(HttpRequestError.SecureConnectionError, $"{origin.Host} negotiated unsupported protocol '{protocol}'."),
            };
            Log.Connected(_logger, origin.Host, origin.Port, profile.Identity.Name, protocol ?? "http/1.1", resumed);
            return connection;
        }
        catch (Exception exception)
        {
            if (stream is not null)
            {
                await stream.DisposeAsync().ConfigureAwait(false);
            }

            if (cancellationToken.IsCancellationRequested)
            {
                throw exception as OperationCanceledException ?? new OperationCanceledException("Connecting was canceled.", exception, cancellationToken);
            }

            Log.ConnectFailed(_logger, origin.Host, origin.Port, exception);

            // A timed-out TLS handshake surfaces as an I/O error from the aborted stream, not as a cancellation.
            if (timeout.IsCancellationRequested)
            {
                throw new HttpRequestException(HttpRequestError.ConnectionError,
                    $"Connecting to {origin.Host}:{origin.Port} timed out after {_connectTimeout}.", new TimeoutException(exception.Message, exception));
            }

            if (exception is SocketException)
            {
                throw new HttpRequestException(HttpRequestError.ConnectionError, $"Connecting to {origin.Host}:{origin.Port} failed.", exception);
            }

            if (exception is IOException && secure)
            {
                throw new HttpRequestException(HttpRequestError.SecureConnectionError, $"The TLS handshake with {origin.Host} failed.", exception);
            }

            throw;
        }
    }

    /// <summary>Two requests may race to connect; the first HTTP/2 connection wins and the other is closed.</summary>
    private Http2Connection Share(Origin origin, Http2Connection connection)
    {
        var shared = _http2.AddOrUpdate(origin, connection, (_, existing) => existing.IsReusable ? existing : connection);
        if (shared != connection)
        {
            connection.Dispose();
        }

        return shared;
    }
}
