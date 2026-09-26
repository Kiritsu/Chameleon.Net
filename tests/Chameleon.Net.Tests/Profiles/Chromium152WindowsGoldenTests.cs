using System.Net.Http.Headers;
using System.Text;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;

namespace Chameleon.Net.Tests.Profiles;

/// <summary>Every expectation here is copied from the 2026-09-26 Chromium 152 captures (tls.peet.ws and a local capture server).</summary>
public sealed class Chromium152WindowsGoldenTests
{
    private static readonly ClientProfile Profile = BuiltInProfiles.Chromium152Windows;

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Ja4MatchesTheCaptureOnEveryConnection()
    {
        for (var i = 0; i < 10; i++)
        {
            var fingerprint = TlsFingerprinter.Compute(ClientHelloParser.Parse(await ClientHelloCapture.CaptureAsync(Profile.Tls, "tls.peet.ws")));

            Assert.Equal("t13d1516h2_8daaf6152771_806a8c22fdea", fingerprint.Ja4);
            Assert.Equal(
                "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
                + "_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01"
                + "_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601",
                fingerprint.Ja4Raw);
        }
    }

    [Fact]
    public void AkamaiMatchesTheCapture()
    {
        Assert.Equal("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", AkamaiFingerprint.Compute(Profile.Http2));
    }

    [Fact]
    public async Task Http1FetchMatchesTheCapture()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = new HttpClient(new ChameleonHttpMessageHandler(Profile));

        await client.GetStringAsync(server.Url("/fetch-get"), CancellationToken);

        var sent = Assert.Single(server.Requests);
        Assert.Equal(
            ["Host", "Connection", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "sec-ch-ua-mobile", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode",
                "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"],
            sent.HeaderNames);
        Assert.Equal("keep-alive", sent.Header("Connection"));
    }

    [Fact]
    public async Task Http1PostMatchesTheCapture()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = new HttpClient(new ChameleonHttpMessageHandler(Profile));
        using var request = new HttpRequestMessage(HttpMethod.Post, server.Url("/fetch-post"))
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes("""{"a":1}""")) { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } },
        };
        request.Headers.Add("Origin", server.Url("/").GetLeftPart(UriPartial.Authority));
        request.Headers.Referrer = server.Url("/");

        (await client.SendAsync(request, CancellationToken)).Dispose();

        Assert.Equal(
            ["Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "Content-Type", "sec-ch-ua-mobile", "Accept",
                "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language"],
            Assert.Single(server.Requests).HeaderNames);
    }

    [Fact]
    public async Task Http1NavigationMatchesTheCapture()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = new HttpClient(new ChameleonHttpMessageHandler(Profile));
        using var request = new HttpRequestMessage(HttpMethod.Get, server.Url("/"));
        request.Options.Set(ChameleonRequestOptions.Kind, RequestKind.Navigate);

        (await client.SendAsync(request, CancellationToken)).Dispose();

        var sent = Assert.Single(server.Requests);
        Assert.Equal(
            ["Host", "Connection", "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User",
                "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"],
            sent.HeaderNames);
        Assert.Equal("navigate", sent.Header("Sec-Fetch-Mode"));
    }

    [Fact]
    public async Task WebSocketHandshakeMatchesTheCapture()
    {
        await using var server = new LoopbackWebSocketServer();
        var options = new ChameleonWebSocketOptions();
        options.Headers.Add(new("Origin", $"http://127.0.0.1:{server.Port}"));

        using var webSocket = await new ChameleonWebSocketConnector().ConnectAsync(server.Uri, Profile, options, CancellationToken);
        var lines = (await server.RequestHead).Split("\r\n");

        Assert.Equal(
            ["Host", "Connection", "Pragma", "Cache-Control", "User-Agent", "Upgrade", "Origin", "Sec-WebSocket-Version", "Accept-Encoding",
                "Accept-Language", "Sec-WebSocket-Key", "Sec-WebSocket-Extensions"],
            lines[1..].Select(static line => line[..line.IndexOf(':', StringComparison.Ordinal)]));
        Assert.Contains("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits", lines);
        Assert.Contains("Pragma: no-cache", lines);
    }
}
