using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;

namespace Chameleon.Net.Tests.Profiles;

/// <summary>Every expectation here is copied from the 2026-09-26 Edge 153 captures (tls.peet.ws and a local capture server that sets a cookie).</summary>
public sealed class Edge153WindowsGoldenTests
{
    private static readonly ClientProfile Profile = BuiltInProfiles.Edge153Windows;

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Ja4AndAkamaiMatchTheCapture()
    {
        var fingerprint = TlsFingerprinter.Compute(ClientHelloParser.Parse(await ClientHelloCapture.CaptureAsync(Profile.Tls, "tls.peet.ws")));

        Assert.Equal("t13d1516h2_8daaf6152771_806a8c22fdea", fingerprint.Ja4);
        Assert.Equal("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", AkamaiFingerprint.Compute(Profile.Http2));
    }

    /// <summary>Edge's WebSocket connections offer http/1.1 alone and send no ALPS. The capture (Edge 154, same TLS stack) was a resumed
    /// connection: JA4 <c>t13d1516h1_8daaf6152771_3bf25d69fb96</c>, i.e. our fresh WebSocket hello plus pre_shared_key.</summary>
    [Fact]
    public async Task WebSocketClientHelloHasNoAlpsLikeTheCapture()
    {
        var tls = Profile.Tls.WithAlpn(Profile.WebSocket.Alpn!);
        var fingerprint = TlsFingerprinter.Compute(ClientHelloParser.Parse(await ClientHelloCapture.CaptureAsync(tls, "tls.peet.ws")));

        Assert.DoesNotContain(tls.Extensions, static e => e is ApplicationSettingsExtension);
        Assert.StartsWith("t13d1515h1_8daaf6152771_", fingerprint.Ja4, StringComparison.Ordinal);
        var parts = fingerprint.Ja4Raw.Split('_');
        var resumedExtensions = string.Join(',', parts[2].Split(',').Append("0029").Order(StringComparer.Ordinal));
        var resumedHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.ASCII.GetBytes($"{resumedExtensions}_{parts[3]}")))[..12];
        Assert.Equal("3bf25d69fb96", resumedHash);
    }

    [Fact]
    public async Task Http1NavigationSendsClientHints()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = new HttpClient(new ChameleonHttpMessageHandler(Profile));
        using var request = new HttpRequestMessage(HttpMethod.Get, server.Url("/"));
        request.Options.Set(ChameleonRequestOptions.Kind, RequestKind.Navigate);

        (await client.SendAsync(request, CancellationToken)).Dispose();

        var sent = Assert.Single(server.Requests);
        Assert.Equal(
            ["Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent", "Accept",
                "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"],
            sent.HeaderNames);
        Assert.Equal("\"Microsoft Edge\";v=\"153\", \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"153\"", sent.Header("sec-ch-ua"));
        Assert.EndsWith(" Edg/153.0.0.0", sent.Header("User-Agent"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Http1PostWithCookieMatchesTheCapture()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        var cookies = new CookieContainer();
        cookies.Add(server.Url("/"), new Cookie("seen", "1"));
        using var client = new HttpClient(new ChameleonHttpMessageHandler(Profile, new ChameleonOptions { Cookies = cookies }));
        using var request = new HttpRequestMessage(HttpMethod.Post, server.Url("/fetch-post"))
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes("""{"a":1}""")) { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } },
        };
        request.Headers.Add("Origin", server.Url("/").GetLeftPart(UriPartial.Authority));
        request.Headers.Referrer = server.Url("/");

        (await client.SendAsync(request, CancellationToken)).Dispose();

        Assert.Equal(
            ["Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "Content-Type", "sec-ch-ua-mobile", "Accept",
                "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language", "Cookie"],
            Assert.Single(server.Requests).HeaderNames);
    }

    [Fact]
    public async Task WebSocketHandshakeWithCookieMatchesTheCapture()
    {
        await using var server = new LoopbackWebSocketServer();
        var cookies = new CookieContainer();
        cookies.Add(new Uri($"http://127.0.0.1:{server.Port}/"), new Cookie("seen", "1"));
        var options = new ChameleonWebSocketOptions();
        options.Headers.Add(new("Origin", $"http://127.0.0.1:{server.Port}"));

        using var webSocket = await new ChameleonWebSocketConnector(new ChameleonOptions { Cookies = cookies })
            .ConnectAsync(server.Uri, Profile, options, CancellationToken);
        var lines = (await server.RequestHead).Split("\r\n");

        Assert.Equal(
            ["Host", "Connection", "Pragma", "Cache-Control", "User-Agent", "Upgrade", "Origin", "Sec-WebSocket-Version", "Accept-Encoding",
                "Accept-Language", "Cookie", "Sec-WebSocket-Key", "Sec-WebSocket-Extensions"],
            lines[1..].Select(static line => line[..line.IndexOf(':', StringComparison.Ordinal)]));
    }
}
