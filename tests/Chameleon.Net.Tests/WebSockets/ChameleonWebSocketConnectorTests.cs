using System.Net;
using System.Net.WebSockets;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;

namespace Chameleon.Net.Tests.WebSockets;

/// <summary>Handshake and framing against a loopback ws:// server — the TLS layer is covered elsewhere.</summary>
public sealed class ChameleonWebSocketConnectorTests
{
    private static readonly ClientProfile Profile = BuiltInProfiles.OkHttp4Android13;

    private readonly ChameleonWebSocketConnector _connector = new();

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task RequestHeadFollowsProfileOrder()
    {
        await using var server = new LoopbackWebSocketServer();
        var options = new ChameleonWebSocketOptions();
        options.Headers.Add(new("Authorization", "Bearer token"));

        using var webSocket = await _connector.ConnectAsync(server.Uri, Profile, options, CancellationToken);
        var lines = (await server.RequestHead).Split("\r\n");

        Assert.Equal("GET /chat?room=1 HTTP/1.1", lines[0]);
        Assert.Equal(
            ["Authorization", "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Host", "Accept-Encoding", "User-Agent"],
            lines[1..].Select(static line => line[..line.IndexOf(':', StringComparison.Ordinal)]));
        Assert.Contains("Connection: Upgrade", lines);
        Assert.Contains("Sec-WebSocket-Version: 13", lines);
        Assert.Contains("Sec-WebSocket-Extensions: permessage-deflate", lines);
        Assert.Contains($"Host: 127.0.0.1:{server.Port}", lines);
        Assert.Contains("Accept-Encoding: gzip", lines);
        Assert.Contains("User-Agent: okhttp/4.12.0", lines);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("permessage-deflate")]
    [InlineData("permessage-deflate; server_no_context_takeover; client_max_window_bits=10")]
    public async Task EchoesMessages(string? acceptedExtensions)
    {
        await using var server = new LoopbackWebSocketServer(acceptedExtensions);
        using var webSocket = await _connector.ConnectAsync(server.Uri, Profile, cancellationToken: CancellationToken);

        foreach (var message in new[] { "hello", string.Concat(Enumerable.Repeat("compressible ", 20_000)) })
        {
            await webSocket.SendTextAsync(message, CancellationToken);
            Assert.Equal(message, await webSocket.ReceiveTextAsync(CancellationToken));
        }

        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken);
        Assert.Equal(WebSocketState.Closed, webSocket.State);
    }

    [Fact]
    public async Task KeepsFrameSentWithTheUpgradeResponse()
    {
        await using var server = new LoopbackWebSocketServer(sentWithUpgrade: [0x81, 0x05, .. "hello"u8]);
        using var webSocket = await _connector.ConnectAsync(server.Uri, Profile, cancellationToken: CancellationToken);

        Assert.Equal("hello", await webSocket.ReceiveTextAsync(CancellationToken));
    }

    [Fact]
    public async Task RejectedUpgradeCarriesStatusAndHeaders()
    {
        await using var server = new LoopbackWebSocketServer(respond: static _ =>
            "HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\nContent-Length: 0\r\n\r\n");

        var exception = await Assert.ThrowsAsync<WebSocketException>(() => _connector.ConnectAsync(server.Uri, Profile, cancellationToken: CancellationToken));

        var rejection = Assert.IsType<WebSocketUpgradeRejectedException>(exception.InnerException);
        Assert.Equal(HttpStatusCode.Forbidden, rejection.StatusCode);
        Assert.Contains(new KeyValuePair<string, string>("cf-mitigated", "challenge"), rejection.ResponseHeaders);
    }

    [Fact]
    public async Task WrongAcceptKeyIsRejected()
    {
        await using var server = new LoopbackWebSocketServer(respond: static _ =>
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: bogus\r\n\r\n");

        var exception = await Assert.ThrowsAsync<WebSocketException>(() => _connector.ConnectAsync(server.Uri, Profile, cancellationToken: CancellationToken));

        Assert.Equal(WebSocketError.HeaderError, exception.WebSocketErrorCode);
    }

    [Fact]
    public async Task ExtensionThatWasNotOfferedIsRejected()
    {
        var noDeflate = Profile with { WebSocket = Profile.WebSocket with { PerMessageDeflateOffer = null } };
        await using var server = new LoopbackWebSocketServer(acceptedExtensions: "permessage-deflate");

        var exception = await Assert.ThrowsAsync<WebSocketException>(() => _connector.ConnectAsync(server.Uri, noDeflate, cancellationToken: CancellationToken));

        Assert.Equal(WebSocketError.HeaderError, exception.WebSocketErrorCode);
    }

    [Fact]
    public async Task TruncatedResponseIsAHeaderError()
    {
        await using var server = new LoopbackWebSocketServer(respond: static _ => "HTTP/1.1 101 Switching");

        var exception = await Assert.ThrowsAsync<WebSocketException>(() => _connector.ConnectAsync(server.Uri, Profile, cancellationToken: CancellationToken));

        Assert.IsType<HttpIOException>(exception.InnerException);
    }

    [Theory]
    [InlineData("Host", "evil.example")]
    [InlineData("Sec-WebSocket-Key", "x")]
    [InlineData("X-Injected", "value\r\nEvil: 1")]
    [InlineData("Bad Name", "value")]
    public async Task InvalidHeadersAreRejectedBeforeConnecting(string name, string value)
    {
        var options = new ChameleonWebSocketOptions();
        options.Headers.Add(new(name, value));

        // Nothing listens on port 1: an ArgumentException (not a SocketException) proves no connection was attempted.
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _connector.ConnectAsync(new Uri("ws://127.0.0.1:1/"), Profile, options, CancellationToken));
    }
}
