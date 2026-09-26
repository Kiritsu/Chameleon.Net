using System.Net;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Microsoft.AspNetCore.Builder;

namespace Chameleon.Net.Tests.Http;

public sealed class ProxyTests
{
    private static readonly NetworkCredential Credentials = new("user", "p@ss");

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    /// <summary>https targets are tunnelled; so is HTTP/2 prior knowledge, which a forward proxy couldn't carry.</summary>
    [Fact]
    public async Task TunnelsUseConnectWithPreemptiveBasicAuth()
    {
        await using var target = await KestrelHttp2Server.StartAsync(static app => app.MapGet("/", static () => "via proxy"));
        await using var proxy = new LoopbackProxy(ProxyKind.HttpConnect, Credentials);
        using var client = Client(new FixedProxy(proxy.Uri("user:p%40ss")));
        client.DefaultRequestVersion = HttpVersion.Version20;
        client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact;

        Assert.Equal("via proxy", await client.GetStringAsync(target.Url("/"), CancellationToken));

        var lines = Assert.Single(proxy.Handshakes).Split("\r\n");
        Assert.Equal($"CONNECT 127.0.0.1:{target.Url("/").Port} HTTP/1.1", lines[0]);
        Assert.Equal(
            [$"Host: 127.0.0.1:{target.Url("/").Port}", "Proxy-Connection: Keep-Alive", "User-Agent: okhttp/4.12.0", "Proxy-Authorization: Basic dXNlcjpwQHNz"],
            lines[1..]);
    }

    /// <summary>OkHttp doesn't tunnel plain http: it sends the request itself to the proxy, with the full URL as the target.</summary>
    [Fact]
    public async Task PlainHttpIsSentToTheProxyInAbsoluteForm()
    {
        await using var target = new LoopbackHttpServer(static _ => Reply.Ok("via proxy"));
        await using var proxy = new LoopbackProxy(ProxyKind.HttpConnect, Credentials);
        using var client = Client(new FixedProxy(proxy.Uri("user:p%40ss")));

        Assert.Equal("via proxy", await client.GetStringAsync(target.Url("/a?b=1"), CancellationToken));

        var lines = Assert.Single(proxy.Handshakes).Split("\r\n");
        Assert.Equal($"GET http://127.0.0.1:{target.Port}/a?b=1 HTTP/1.1", lines[0]);
        Assert.Equal(
            [$"Host: 127.0.0.1:{target.Port}", "Connection: Keep-Alive", "Accept-Encoding: gzip", "User-Agent: okhttp/4.12.0", "Proxy-Authorization: Basic dXNlcjpwQHNz"],
            lines[1..]);
    }

    [Fact]
    public async Task ProxyCredentialsCanComeFromTheWebProxy()
    {
        await using var target = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        await using var proxy = new LoopbackProxy(ProxyKind.HttpConnect, Credentials);
        using var client = Client(new FixedProxy(proxy.Uri()) { Credentials = Credentials });

        Assert.Equal("ok", await client.GetStringAsync(target.Url("/"), CancellationToken));
    }

    [Fact]
    public async Task RejectedTunnelIsAProxyTunnelError()
    {
        await using var target = new LoopbackHttpServer(static _ => Reply.Ok("unreachable"));
        await using var proxy = new LoopbackProxy(ProxyKind.HttpConnect, Credentials);
        using var client = Client(new FixedProxy(proxy.Uri()));
        using var tunnelled = new HttpRequestMessage(HttpMethod.Get, target.Url("/"))
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => client.SendAsync(tunnelled, CancellationToken));

        Assert.Equal(HttpRequestError.ProxyTunnelError, exception.HttpRequestError);
        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, exception.StatusCode);
    }

    [Fact]
    public async Task ForwardProxyRejectionIsAnOrdinaryResponse()
    {
        await using var target = new LoopbackHttpServer(static _ => Reply.Ok("unreachable"));
        await using var proxy = new LoopbackProxy(ProxyKind.HttpConnect, Credentials);
        using var client = Client(new FixedProxy(proxy.Uri()));

        using var response = await client.GetAsync(target.Url("/"), CancellationToken);

        Assert.Equal(HttpStatusCode.ProxyAuthenticationRequired, response.StatusCode);
    }

    [Fact]
    public async Task Socks5ProxyAuthenticatesWithUsernameAndPassword()
    {
        await using var target = new LoopbackHttpServer(static _ => Reply.Ok("via socks"));
        await using var proxy = new LoopbackProxy(ProxyKind.Socks5, Credentials);
        using var client = Client(new FixedProxy(proxy.Uri("user:p%40ss")));

        Assert.Equal("via socks", await client.GetStringAsync(target.Url("/"), CancellationToken));
        Assert.Equal($"methods=0,2 user=user type=1 target=127.0.0.1:{target.Port}", Assert.Single(proxy.Handshakes));
    }

    [Fact]
    public async Task Socks5LeavesHostNameResolutionToTheProxy()
    {
        await using var target = new LoopbackHttpServer(static _ => Reply.Ok("resolved remotely"));
        await using var proxy = new LoopbackProxy(ProxyKind.Socks5);
        using var client = Client(new FixedProxy(proxy.Uri()));

        Assert.Equal("resolved remotely", await client.GetStringAsync(new Uri($"http://localhost:{target.Port}/"), CancellationToken));
        Assert.Equal($"methods=0 type=3 target=localhost:{target.Port}", Assert.Single(proxy.Handshakes));
    }

    [Fact]
    public async Task Socks5WithoutRequiredCredentialsIsAProxyTunnelError()
    {
        await using var target = new LoopbackHttpServer(static _ => Reply.Ok("unreachable"));
        await using var proxy = new LoopbackProxy(ProxyKind.Socks5, Credentials);
        using var client = Client(new FixedProxy(proxy.Uri()));

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetStringAsync(target.Url("/"), CancellationToken));

        Assert.Equal(HttpRequestError.ProxyTunnelError, exception.HttpRequestError);
    }

    [Fact]
    public async Task Http2WorksThroughTheTunnel()
    {
        await using var target = await KestrelHttp2Server.StartAsync(static app => app.MapGet("/", static () => "h2 via proxy"));
        await using var proxy = new LoopbackProxy(ProxyKind.HttpConnect);
        using var client = Client(new FixedProxy(proxy.Uri()));
        client.DefaultRequestVersion = HttpVersion.Version20;
        client.DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact;

        using var response = await client.GetAsync(target.Url("/"), CancellationToken);

        Assert.Equal(HttpVersion.Version20, response.Version);
        Assert.Equal("h2 via proxy", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public void HttpsProxiesAreRejectedUpFront()
    {
        Assert.Throws<NotSupportedException>(() =>
            new ChameleonHttpMessageHandler(BuiltInProfiles.OkHttp4Android13, new ChameleonOptions { Proxy = new WebProxy("https://proxy.example:443") }));
    }

    private static HttpClient Client(IWebProxy proxy) =>
        new(new ChameleonHttpMessageHandler(BuiltInProfiles.OkHttp4Android13, new ChameleonOptions { Proxy = proxy }));
}
