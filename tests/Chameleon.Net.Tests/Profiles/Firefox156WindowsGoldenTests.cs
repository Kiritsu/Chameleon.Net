using System.Buffers.Binary;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;

namespace Chameleon.Net.Tests.Profiles;

/// <summary>Every expectation here is copied from the 2026-09-26 Firefox 156 captures (tls.peet.ws and a local capture server).</summary>
public sealed class Firefox156WindowsGoldenTests
{
    private static readonly ClientProfile Profile = BuiltInProfiles.Firefox156Windows;

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Ja3AndJa4MatchTheCaptureOnEveryConnection()
    {
        for (var i = 0; i < 5; i++)
        {
            var fingerprint = TlsFingerprinter.Compute(ClientHelloParser.Parse(await ClientHelloCapture.CaptureAsync(Profile.Tls, "tls.peet.ws")));

            Assert.Equal(
                "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037,"
                + "4588-29-23-24-25,0",
                fingerprint.Ja3);
            Assert.Equal("9d42e90b0225e779f03141ddcd699df2", fingerprint.Ja3Hash);
            Assert.Equal("t13d1517h2_8daaf6152771_3cbfd9057e0d", fingerprint.Ja4);
            Assert.Equal(
                "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
                + "_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01"
                + "_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201",
                fingerprint.Ja4Raw);
        }
    }

    [Fact]
    public async Task GreaseEchHasNssShape()
    {
        var aeads = new HashSet<ushort>();
        for (var i = 0; i < 20; i++)
        {
            var ech = Extension(await ClientHelloCapture.CaptureAsync(Profile.Tls, "tls.peet.ws"), 65037);

            Assert.Equal(282, ech.Length);
            Assert.Equal(0x0001, BinaryPrimitives.ReadUInt16BigEndian(ech.AsSpan(1)));
            aeads.Add(BinaryPrimitives.ReadUInt16BigEndian(ech.AsSpan(3)));
            Assert.Equal(32, BinaryPrimitives.ReadUInt16BigEndian(ech.AsSpan(6)));
            Assert.Equal(240, BinaryPrimitives.ReadUInt16BigEndian(ech.AsSpan(8 + 32)));
        }

        Assert.Equal(new ushort[] { 0x0001, 0x0003 }, aeads.Order());
    }

    [Fact]
    public async Task KeySharesAndRecordSizeLimitMatchTheCapture()
    {
        var record = await ClientHelloCapture.CaptureAsync(Profile.Tls, "tls.peet.ws");

        Assert.Equal("4001", Convert.ToHexString(Extension(record, 28)));
        var shares = Extension(record, 51).AsSpan(2);
        var sizes = new List<(ushort Group, int Length)>();
        while (!shares.IsEmpty)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(shares[2..]);
            sizes.Add((BinaryPrimitives.ReadUInt16BigEndian(shares), length));
            shares = shares[(4 + length)..];
        }

        Assert.Equal([(0x11EC, 1216), (29, 32), (23, 65)], sizes);
    }

    [Fact]
    public void AkamaiMatchesTheCapture()
    {
        Assert.Equal("1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s", AkamaiFingerprint.Compute(Profile.Http2));
    }

    [Fact]
    public async Task Http1FetchMatchesTheCapture()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = new HttpClient(new ChameleonHttpMessageHandler(Profile));

        await client.GetStringAsync(server.Url("/fetch-get"), CancellationToken);

        var sent = Assert.Single(server.Requests);
        Assert.Equal(
            ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Priority"],
            sent.HeaderNames);
        Assert.Equal("u=4", sent.Header("Priority"));
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
            ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer", "Content-Type", "Content-Length", "Origin", "Connection",
                "Cookie", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Priority"],
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
            ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest",
                "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User", "Priority"],
            sent.HeaderNames);
        Assert.Equal("u=0, i", sent.Header("Priority"));
    }

    [Fact]
    public async Task WebSocketHandshakeMatchesTheCapture()
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
            ["Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Sec-WebSocket-Version", "Origin", "Sec-WebSocket-Extensions",
                "Sec-WebSocket-Key", "Connection", "Cookie", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Pragma", "Cache-Control", "Upgrade"],
            lines[1..].Select(static line => line[..line.IndexOf(':', StringComparison.Ordinal)]));
        Assert.Contains("Sec-WebSocket-Extensions: permessage-deflate", lines);
        Assert.Contains("Sec-Fetch-Mode: websocket", lines);
    }

    private static byte[] Extension(byte[] record, ushort type)
    {
        var body = record.AsSpan(5 + 4);
        var offset = 2 + 32;
        offset += 1 + body[offset];
        offset += 2 + BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 1 + body[offset];
        var extensions = body.Slice(offset + 2, BinaryPrimitives.ReadUInt16BigEndian(body[offset..]));
        while (!extensions.IsEmpty)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(extensions[2..]);
            if (BinaryPrimitives.ReadUInt16BigEndian(extensions) == type)
            {
                return extensions.Slice(4, length).ToArray();
            }

            extensions = extensions[(4 + length)..];
        }

        throw new InvalidOperationException($"No extension {type}.");
    }
}
