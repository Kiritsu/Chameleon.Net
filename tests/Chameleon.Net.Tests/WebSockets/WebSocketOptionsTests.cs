using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;

namespace Chameleon.Net.Tests.WebSockets;

/// <summary><see cref="ChameleonOptions"/> applied to WebSocket connections.</summary>
public sealed class WebSocketOptionsTests
{
    private static readonly ClientProfile Profile = BuiltInProfiles.OkHttp4Android13;

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ConnectsThroughAnHttpProxy()
    {
        await using var server = new LoopbackWebSocketServer();
        await using var proxy = new LoopbackProxy(ProxyKind.HttpConnect);
        var connector = new ChameleonWebSocketConnector(new ChameleonOptions { Proxy = new FixedProxy(proxy.Uri()) });

        using var webSocket = await connector.ConnectAsync(server.Uri, Profile, cancellationToken: CancellationToken);
        await webSocket.SendTextAsync("through the proxy", CancellationToken);

        Assert.Equal("through the proxy", await webSocket.ReceiveTextAsync(CancellationToken));
        // ws:// is plain http: OkHttp sends the upgrade to the proxy in absolute form rather than tunnelling.
        Assert.StartsWith($"GET http://127.0.0.1:{server.Port}/chat?room=1 HTTP/1.1", Assert.Single(proxy.Handshakes), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ConnectsThroughASocks5Proxy()
    {
        await using var server = new LoopbackWebSocketServer();
        await using var proxy = new LoopbackProxy(ProxyKind.Socks5);
        var connector = new ChameleonWebSocketConnector(new ChameleonOptions { Proxy = new FixedProxy(proxy.Uri()) });

        using var webSocket = await connector.ConnectAsync(server.Uri, Profile, cancellationToken: CancellationToken);
        await webSocket.SendTextAsync("socks", CancellationToken);

        Assert.Equal("socks", await webSocket.ReceiveTextAsync(CancellationToken));
    }

    [Fact]
    public async Task CookiesAreSentInProfilePositionAndStoredFromTheUpgrade()
    {
        await using var server = new LoopbackWebSocketServer(upgradeHeaders: ["Set-Cookie: session=new; Path=/"]);
        var cookies = new CookieContainer();
        cookies.Add(new Uri($"http://127.0.0.1:{server.Port}/"), new Cookie("seen", "1"));
        var connector = new ChameleonWebSocketConnector(new ChameleonOptions { Cookies = cookies });

        using var webSocket = await connector.ConnectAsync(server.Uri, Profile, cancellationToken: CancellationToken);
        var lines = (await server.RequestHead).Split("\r\n");

        Assert.Contains("Cookie: seen=1", lines);
        Assert.Equal(["Host", "Accept-Encoding", "Cookie", "User-Agent"], lines[^4..].Select(static l => l[..l.IndexOf(':', StringComparison.Ordinal)]));
        Assert.Equal("new", cookies.GetCookies(new Uri($"http://127.0.0.1:{server.Port}/"))["session"]?.Value);
    }

    [Fact]
    public async Task ConnectTimeoutCoversTheTlsHandshake()
    {
        // Accepts TCP connections but never answers the ClientHello.
        using var silent = new TcpListener(IPAddress.Loopback, 0);
        silent.Start();
        var port = ((IPEndPoint)silent.LocalEndpoint).Port;
        var connector = new ChameleonWebSocketConnector(new ChameleonOptions { ConnectTimeout = TimeSpan.FromMilliseconds(300) });

        var exception = await Assert.ThrowsAsync<WebSocketException>(() =>
            connector.ConnectAsync(new Uri($"wss://127.0.0.1:{port}/"), Profile, cancellationToken: CancellationToken)).WaitAsync(TimeSpan.FromSeconds(10), CancellationToken);

        Assert.IsType<TimeoutException>(exception.InnerException);
    }
}
