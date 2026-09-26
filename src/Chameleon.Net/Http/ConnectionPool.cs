using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Chameleon.Net.Http.Http1;
using Chameleon.Net.Http.Http2;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;

namespace Chameleon.Net.Http;

/// <summary>Per origin: one shared HTTP/2 connection, or a stack of idle HTTP/1.1 connections. ALPN decides which one a new connection becomes.</summary>
internal sealed class ConnectionPool : IDisposable
{
    /// <summary>Below the usual 60–75 s server keep-alive timeouts; stale connections that slip through are retried anyway.</summary>
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(50);

    private readonly ConcurrentDictionary<Origin, ConcurrentStack<Http1Connection>> _idle = new();
    private readonly ConcurrentDictionary<Origin, Http2Connection> _http2 = new();
    private readonly IProfileSelector _profileSelector;
    private readonly ITlsConnectionFactory _tlsConnectionFactory;
    private readonly ITransport _transport;
    private readonly TimeSpan _connectTimeout;
    private volatile bool _disposed;

    public ConnectionPool(IProfileSelector profileSelector, ITlsConnectionFactory tlsConnectionFactory, ITransport transport, TimeSpan connectTimeout)
    {
        _profileSelector = profileSelector;
        _tlsConnectionFactory = tlsConnectionFactory;
        _transport = transport;
        _connectTimeout = connectTimeout;
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

            // Going away: in-flight streams finish on their own, new ones go elsewhere.
            _http2.TryRemove(new KeyValuePair<Origin, Http2Connection>(origin, shared));
        }

        if (!http2PriorKnowledge && _idle.TryGetValue(origin, out var idle))
        {
            while (idle.TryPop(out var connection))
            {
                if (connection.IsReusable && connection.IdleTime < IdleTimeout)
                {
                    connection.MarkReused();
                    return connection;
                }

                connection.Dispose();
            }
        }

        return await ConnectAsync(origin, _profileSelector.SelectForConnection(origin), secure, http2PriorKnowledge, cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        _disposed = true;
        foreach (var idle in _idle.Values)
        {
            while (idle.TryPop(out var connection))
            {
                connection.Dispose();
            }
        }

        foreach (var connection in _http2.Values)
        {
            connection.Dispose();
        }

        _http2.Clear();
    }

    private void Release(Http1Connection connection)
    {
        if (_disposed)
        {
            connection.Dispose();
            return;
        }

        connection.MarkIdle();
        _idle.GetOrAdd(connection.Origin, static _ => new ConcurrentStack<Http1Connection>()).Push(connection);
    }

    private async Task<IHttpConnection> ConnectAsync(Origin origin, ClientProfile profile, bool secure, bool http2PriorKnowledge, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_connectTimeout);

        Stream? stream = null;
        try
        {
            string? protocol;
            if (secure)
            {
                var tls = await _tlsConnectionFactory.ConnectAsync(_transport, origin.Host, origin.Port, profile.Tls, timeout.Token).ConfigureAwait(false);
                stream = tls.Stream;
                protocol = tls.NegotiatedProtocol;
            }
            else
            {
                stream = await _transport.ConnectAsync(new DnsEndPoint(origin.Host, origin.Port), timeout.Token).ConfigureAwait(false);
                protocol = http2PriorKnowledge ? "h2" : null;
            }

            switch (protocol)
            {
                case "h2":
                    var http2 = await Http2Connection.OpenAsync(origin, profile, stream, timeout.Token).ConfigureAwait(false);
                    return Share(origin, http2);
                case null or "http/1.1":
                    return new Http1Connection(origin, profile, stream, Release);
                default:
                    throw new HttpRequestException(HttpRequestError.SecureConnectionError, $"{origin.Host} negotiated unsupported protocol '{protocol}'.");
            }
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
