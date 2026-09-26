using System.Collections.Frozen;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using Chameleon.Net.Http;
using Chameleon.Net.Http.Http1;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Chameleon.Net.WebSockets;

public sealed class ChameleonWebSocketConnector : IWebSocketConnector
{
    private const string AcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private static readonly FrozenSet<string> ReservedHeaders = FrozenSet.Create(StringComparer.OrdinalIgnoreCase,
        "Host", "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol");

    private readonly ITlsConnectionFactory _tlsConnectionFactory;
    private readonly ProxyRouting _routing;
    private readonly TimeSpan _connectTimeout;
    private readonly CookieContainer? _cookies;
    private readonly ILogger _logger = NullLogger.Instance;

    /// <summary>Direct TCP, profile-driven TLS, OS trust store validation.</summary>
    public ChameleonWebSocketConnector()
        : this(new ChameleonOptions())
    {
    }

    /// <summary>Uses <see cref="ChameleonOptions.Proxy"/>, <see cref="ChameleonOptions.CertificateValidator"/>, <see cref="ChameleonOptions.ConnectTimeout"/>
    /// and <see cref="ChameleonOptions.Cookies"/>; the profile is chosen per call.</summary>
    public ChameleonWebSocketConnector(ChameleonOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.TcpFingerprintApplicator is not null)
        {
            throw new NotSupportedException("TcpFingerprintApplicator is not supported yet.");
        }

        ProxyRouting.Validate(options.Proxy);
        var random = new Org.BouncyCastle.Security.SecureRandom();
        _tlsConnectionFactory = new BouncyCastleTlsConnectionFactory(
            new ProfileTlsClientFactory(), new ClientHelloEncoder(random), options.CertificateValidator ?? new SystemCertificateValidator(), random)
        {
            ResumeSessions = options.TlsSessionResumption,
            SessionCache = options.TlsSessionCache ?? new TlsSessionCache(),
        };
        _routing = new ProxyRouting(new TcpTransport(), options.Proxy);
        _connectTimeout = options.ConnectTimeout;
        _cookies = options.Cookies;
        _logger = options.LoggerFactory?.CreateLogger(Log.Category) ?? NullLogger.Instance;
    }

    public ChameleonWebSocketConnector(ITlsConnectionFactory tlsConnectionFactory, ITransport transport)
    {
        ArgumentNullException.ThrowIfNull(tlsConnectionFactory);
        ArgumentNullException.ThrowIfNull(transport);

        _tlsConnectionFactory = tlsConnectionFactory;
        _routing = new ProxyRouting(transport, null);
        _connectTimeout = Timeout.InfiniteTimeSpan;
    }

    public async Task<WebSocket> ConnectAsync(Uri uri, ClientProfile profile, ChameleonWebSocketOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(uri);
        ArgumentNullException.ThrowIfNull(profile);
        if (!uri.IsAbsoluteUri || uri.Scheme is not ("ws" or "wss"))
        {
            throw new ArgumentException("Expected an absolute ws:// or wss:// URI.", nameof(uri));
        }

        options ??= new ChameleonWebSocketOptions();
        var httpUri = HttpEquivalent(uri);
        var cookieHeader = _cookies is not null && !options.Headers.Any(static h => string.Equals(h.Key, "Cookie", StringComparison.OrdinalIgnoreCase))
            ? _cookies.GetCookieHeader(httpUri)
            : null;
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        // ws:// behind an HTTP proxy goes to the proxy in absolute form, as OkHttp sends any plain-http request.
        var forwardProxy = _routing.ForwardProxyFor(httpUri);
        var requestHead = BuildRequestHead(uri, profile, options, key, cookieHeader, forwardProxy is null ? null : httpUri, forwardProxy?.Authorization);

        var (connected, resumed) = await OpenStreamAsync(uri, httpUri, profile, forwardProxy, cancellationToken).ConfigureAwait(false);
        var stream = new HttpReadStream(connected);
        try
        {
            Http1ResponseHead response;
            // Blocking TLS reads ignore the token; closing the stream is what unblocks them.
            await using (cancellationToken.Register(static state => ((Stream)state!).Dispose(), stream).ConfigureAwait(false))
            {
                await stream.WriteAsync(requestHead, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                response = await stream.ReadResponseHeadAsync(cancellationToken).ConfigureAwait(false);
            }

            StoreCookies(httpUri, response);
            if (response.StatusCode != (int)HttpStatusCode.SwitchingProtocols)
            {
                Log.WebSocketRejected(_logger, uri, response.StatusCode);
            }

            var (subProtocol, deflate) = ValidateUpgrade(response, key, profile, options);
            Log.WebSocketUpgraded(_logger, uri, profile.Identity.Name, resumed);
            return WebSocket.CreateFromStream(stream, new WebSocketCreationOptions
            {
                IsServer = false,
                SubProtocol = subProtocol,
                KeepAliveInterval = options.KeepAliveInterval,
                DangerousDeflateOptions = deflate,
            });
        }
        catch (Exception exception)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            if (cancellationToken.IsCancellationRequested && exception is not OperationCanceledException)
            {
                throw new OperationCanceledException("The WebSocket handshake was canceled.", exception, cancellationToken);
            }

            if (exception is HttpIOException)
            {
                throw new WebSocketException(WebSocketError.HeaderError, "The server's handshake response is invalid.", exception);
            }

            throw;
        }
    }

    /// <summary>Cookie scoping and proxy selection use the http(s) form of the URI, as ClientWebSocket does.</summary>
    private static Uri HttpEquivalent(Uri uri) => new UriBuilder(uri) { Scheme = uri.Scheme == "wss" ? "https" : "http", Port = HttpUris.Port(uri) }.Uri;

    private void StoreCookies(Uri httpUri, Http1ResponseHead response)
    {
        if (_cookies is null)
        {
            return;
        }

        foreach (var value in response.GetValues("Set-Cookie"))
        {
            try
            {
                _cookies.SetCookies(httpUri, value);
            }
            catch (CookieException)
            {
                // Malformed cookies are dropped, as browsers do.
            }
        }
    }

    private static byte[] BuildRequestHead(
        Uri uri, ClientProfile profile, ChameleonWebSocketOptions options, string key, string? cookieHeader, Uri? absoluteTarget, string? proxyAuthorization)
    {
        var caller = new List<KeyValuePair<string, string>>();
        foreach (var header in options.Headers)
        {
            if (ReservedHeaders.Contains(header.Key))
            {
                throw new ArgumentException($"'{header.Key}' is part of the WebSocket handshake and cannot be set.", nameof(options));
            }

            caller.Add(header);
        }

        // OkHttp has no sub-protocol API: apps set the header themselves, so it sits with the caller's headers.
        if (options.SubProtocols.Count > 0)
        {
            caller.Add(new("Sec-WebSocket-Protocol", string.Join(", ", options.SubProtocols)));
        }

        var client = new List<KeyValuePair<string, string>>
        {
            new("Upgrade", "websocket"),
            new("Connection", "Upgrade"),
            new("Sec-WebSocket-Key", key),
            new("Sec-WebSocket-Version", "13"),
        };
        if (profile.WebSocket.PerMessageDeflateOffer is { } offer)
        {
            client.Add(new("Sec-WebSocket-Extensions", offer));
        }

        client.Add(new("Host", HttpUris.Authority(uri)));
        if (!string.IsNullOrEmpty(cookieHeader))
        {
            client.Add(new("Cookie", cookieHeader));
        }

        foreach (var (name, value) in profile.Headers.DefaultsFor(RequestKind.WebSocket, http2: false))
        {
            if (!caller.Concat(client).Any(header => string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase)))
            {
                client.Add(new(name, value));
            }
        }

        var ordered = HeaderOrdering.Order(caller, client, profile.WebSocket.HandshakeHeaderOrder, profile.Headers.Http1Casing, profile.Headers.OrderMode);
        if (proxyAuthorization is not null)
        {
            ordered = [.. ordered, new("Proxy-Authorization", proxyAuthorization)];
        }

        return Http1RequestHead.Encode("GET", absoluteTarget?.GetComponents(UriComponents.HttpRequestUrl, UriFormat.UriEscaped) ?? uri.PathAndQuery, ordered);
    }

    private async Task<(Stream Stream, bool Resumed)> OpenStreamAsync(Uri uri, Uri httpUri, ClientProfile profile, ForwardProxy? forwardProxy, CancellationToken cancellationToken)
    {
        var host = HttpUris.ConnectHost(uri);
        var port = HttpUris.Port(uri);
        var transport = _routing.For(httpUri, profile);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_connectTimeout);

        TlsConnection connection;
        try
        {
            if (!HttpUris.IsSecure(uri.Scheme))
            {
                var plain = forwardProxy is null
                    ? await transport.ConnectAsync(new DnsEndPoint(host, port), timeout.Token).ConfigureAwait(false)
                    : await forwardProxy.Transport.ConnectAsync(forwardProxy.Endpoint, timeout.Token).ConfigureAwait(false);
                return (plain, false);
            }

            var tls = profile.WebSocket.Alpn is { } alpn ? profile.Tls.WithAlpn(alpn) : profile.Tls;
            connection = await _tlsConnectionFactory.ConnectAsync(transport, host, port, tls, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested && exception is not ArgumentException)
        {
            var reason = timeout.IsCancellationRequested ? new TimeoutException($"Connecting took longer than {_connectTimeout}.", exception) : exception;
            throw new WebSocketException(WebSocketError.Faulted, $"Unable to connect to {host}:{port}.", reason);
        }

        if (connection.NegotiatedProtocol is not (null or "http/1.1"))
        {
            await connection.Stream.DisposeAsync().ConfigureAwait(false);
            throw new WebSocketException(WebSocketError.UnsupportedProtocol,
                $"The server negotiated '{connection.NegotiatedProtocol}'; WebSockets need http/1.1. Restrict the profile's WebSocket ALPN to http/1.1.");
        }

        return (connection.Stream, connection.SessionResumed);
    }

    private static (string? SubProtocol, WebSocketDeflateOptions? Deflate) ValidateUpgrade(
        Http1ResponseHead response, string key, ClientProfile profile, ChameleonWebSocketOptions options)
    {
        if (response.StatusCode != (int)HttpStatusCode.SwitchingProtocols)
        {
            throw new WebSocketException(WebSocketError.NotAWebSocket,
                $"The server answered the WebSocket upgrade with HTTP {response.StatusCode}.",
                new WebSocketUpgradeRejectedException((HttpStatusCode)response.StatusCode, response.Headers));
        }

        if (!response.HasToken("Upgrade", "websocket") || !response.HasToken("Connection", "Upgrade"))
        {
            throw new WebSocketException(WebSocketError.HeaderError, "The 101 response lacks 'Upgrade: websocket' or 'Connection: Upgrade'.");
        }

#pragma warning disable CA5350 // SHA-1 is mandated by RFC 6455 for Sec-WebSocket-Accept, not a security use.
        var expectedAccept = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + AcceptGuid)));
#pragma warning restore CA5350
        if (!string.Equals(response.GetValue("Sec-WebSocket-Accept"), expectedAccept, StringComparison.Ordinal))
        {
            throw new WebSocketException(WebSocketError.HeaderError, "Sec-WebSocket-Accept does not match the key that was sent.");
        }

        var subProtocol = response.GetValue("Sec-WebSocket-Protocol");
        if (subProtocol is not null && !options.SubProtocols.Contains(subProtocol, StringComparer.OrdinalIgnoreCase))
        {
            throw new WebSocketException(WebSocketError.UnsupportedProtocol, $"The server selected sub-protocol '{subProtocol}', which was not offered.");
        }

        var deflate = PerMessageDeflate.Negotiate(response.GetValues("Sec-WebSocket-Extensions"), profile.WebSocket.PerMessageDeflateOffer is not null);
        return (subProtocol, deflate);
    }
}
