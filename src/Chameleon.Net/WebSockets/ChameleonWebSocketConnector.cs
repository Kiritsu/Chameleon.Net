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

namespace Chameleon.Net.WebSockets;

public sealed class ChameleonWebSocketConnector : IWebSocketConnector
{
    private const string AcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private static readonly FrozenSet<string> ReservedHeaders = FrozenSet.Create(StringComparer.OrdinalIgnoreCase,
        "Host", "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol");

    private readonly ITlsConnectionFactory _tlsConnectionFactory;
    private readonly ITransport _transport;

    /// <summary>Direct TCP, profile-driven TLS, OS trust store validation.</summary>
    public ChameleonWebSocketConnector()
        : this(new BouncyCastleTlsConnectionFactory(), new TcpTransport())
    {
    }

    public ChameleonWebSocketConnector(ITlsConnectionFactory tlsConnectionFactory, ITransport transport)
    {
        ArgumentNullException.ThrowIfNull(tlsConnectionFactory);
        ArgumentNullException.ThrowIfNull(transport);

        _tlsConnectionFactory = tlsConnectionFactory;
        _transport = transport;
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
        var key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var requestHead = BuildRequestHead(uri, profile, options, key);

        var stream = new HttpReadStream(await OpenStreamAsync(uri, profile, cancellationToken).ConfigureAwait(false));
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

            var (subProtocol, deflate) = ValidateUpgrade(response, key, profile, options);
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

    private static byte[] BuildRequestHead(Uri uri, ClientProfile profile, ChameleonWebSocketOptions options, string key)
    {
        var headers = new List<KeyValuePair<string, string>>();
        foreach (var header in options.Headers)
        {
            if (ReservedHeaders.Contains(header.Key))
            {
                throw new ArgumentException($"'{header.Key}' is part of the WebSocket handshake and cannot be set.", nameof(options));
            }

            headers.Add(header);
        }

        if (options.SubProtocols.Count > 0)
        {
            headers.Add(new("Sec-WebSocket-Protocol", string.Join(", ", options.SubProtocols)));
        }

        headers.Add(new("Upgrade", "websocket"));
        headers.Add(new("Connection", "Upgrade"));
        headers.Add(new("Sec-WebSocket-Key", key));
        headers.Add(new("Sec-WebSocket-Version", "13"));
        if (profile.WebSocket.PerMessageDeflateOffer is { } offer)
        {
            headers.Add(new("Sec-WebSocket-Extensions", offer));
        }

        headers.Add(new("Host", HttpUris.Authority(uri)));

        foreach (var (name, value) in profile.Headers.DefaultHeaders)
        {
            if (!headers.Exists(header => string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase)))
            {
                headers.Add(new(name, value));
            }
        }

        var ordered = HeaderOrdering.Order(headers, profile.WebSocket.HandshakeHeaderOrder, profile.Headers.Http1Casing);
        return Http1RequestHead.Encode("GET", uri.PathAndQuery, ordered);
    }

    private async Task<Stream> OpenStreamAsync(Uri uri, ClientProfile profile, CancellationToken cancellationToken)
    {
        var host = HttpUris.ConnectHost(uri);
        var port = HttpUris.Port(uri);

        if (!HttpUris.IsSecure(uri.Scheme))
        {
            return await _transport.ConnectAsync(new DnsEndPoint(host, port), cancellationToken).ConfigureAwait(false);
        }

        var tls = profile.WebSocket.Alpn is { } alpn ? profile.Tls.WithAlpn(alpn) : profile.Tls;
        var connection = await _tlsConnectionFactory.ConnectAsync(_transport, host, port, tls, cancellationToken).ConfigureAwait(false);
        if (connection.NegotiatedProtocol is not (null or "http/1.1"))
        {
            await connection.Stream.DisposeAsync().ConfigureAwait(false);
            throw new WebSocketException(WebSocketError.UnsupportedProtocol,
                $"The server negotiated '{connection.NegotiatedProtocol}'; WebSockets need http/1.1. Restrict the profile's WebSocket ALPN to http/1.1.");
        }

        return connection.Stream;
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
