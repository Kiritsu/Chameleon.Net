using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Http;
using Chameleon.Net.Http.Http2.Hpack;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Tests.Http;

/// <summary>What the client puts on the wire before the server answers: the part HTTP/2 fingerprints are computed from.</summary>
public sealed class Http2PrefaceTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task OkHttpPrefaceMatchesTheProfile()
    {
        var capture = await CaptureAsync(BuiltInProfiles.OkHttp4Android13, request => request.Headers.Add("X-App", "1"));

        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", capture.Magic);
        Assert.Equal(
            [(Type: 4, Stream: 0), (Type: 8, Stream: 0), (Type: 1, Stream: 1)],
            capture.Frames.Select(static f => (Type: (int)f.Type, Stream: f.StreamId)));
        Assert.Equal("000401000000", Convert.ToHexStringLower(capture.Frames[0].Payload));
        Assert.Equal(16711681, BinaryPrimitives.ReadInt32BigEndian(capture.Frames[1].Payload));
        Assert.Equal(0x1 | 0x4, capture.Frames[2].Flags);

        var headers = new HpackDecoder(4096).Decode(capture.Frames[2].Payload);
        Assert.Equal([":method", ":path", ":authority", ":scheme", "x-app", "accept-encoding", "user-agent"], headers.Select(static h => h.Key));
        Assert.Equal("okhttp/4.12.0", headers[^1].Value);

        Assert.Equal("4:16777216|16711681|0|m,p,a,s", capture.Akamai);
        Assert.Equal(AkamaiFingerprint.Compute(BuiltInProfiles.OkHttp4Android13.Http2), capture.Akamai);
    }

    [Fact]
    public async Task ChromiumFetchHeadersFrameMatchesTheCapture()
    {
        var capture = await CaptureAsync(BuiltInProfiles.Chromium152Windows);

        Assert.Equal("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", capture.Akamai);
        var headers = capture.Frames[^1];
        Assert.Equal(0x1 | 0x4 | 0x20, headers.Flags);
        // Exclusive dependency on stream 0, weight 220 (wire 219 = 0xdb).
        Assert.Equal("80000000db", Convert.ToHexStringLower(headers.Payload.AsSpan(0, 5)));
        Assert.Equal(
            [":method", ":authority", ":scheme", ":path", "sec-ch-ua-platform", "user-agent", "sec-ch-ua", "sec-ch-ua-mobile", "accept",
                "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding", "accept-language", "priority"],
            new HpackDecoder(4096).Decode(headers.Payload.AsSpan(5)).Select(static h => h.Key));
    }

    [Fact]
    public async Task FirefoxNavigationHeadersFrameMatchesTheCapture()
    {
        var capture = await CaptureAsync(BuiltInProfiles.Firefox156Windows, static request => request.Options.Set(ChameleonRequestOptions.Kind, RequestKind.Navigate));

        Assert.Equal("1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s", capture.Akamai);
        var headers = capture.Frames[^1];
        // Firefox starts at stream 3; weight 42 (wire 41 = 0x29) on stream 0, not exclusive.
        Assert.Equal(3, headers.StreamId);
        Assert.Equal(0x1 | 0x4 | 0x20, headers.Flags);
        Assert.Equal("0000000029", Convert.ToHexStringLower(headers.Payload.AsSpan(0, 5)));
        var decoded = new HpackDecoder(4096).Decode(headers.Payload.AsSpan(5));
        Assert.Equal(
            [":method", ":path", ":authority", ":scheme", "user-agent", "accept", "accept-language", "accept-encoding", "upgrade-insecure-requests",
                "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user", "priority", "te"],
            decoded.Select(static h => h.Key));
        Assert.Equal("trailers", decoded[^1].Value);
    }

    [Fact]
    public async Task EdgeNavigationHeadersFrameMatchesTheCapture()
    {
        var capture = await CaptureAsync(BuiltInProfiles.Edge153Windows, static request => request.Options.Set(ChameleonRequestOptions.Kind, RequestKind.Navigate));

        var headers = capture.Frames[^1];
        Assert.Equal("80000000ff", Convert.ToHexStringLower(headers.Payload.AsSpan(0, 5)));
        Assert.Equal(
            [":method", ":authority", ":scheme", ":path", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent",
                "accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language", "priority"],
            new HpackDecoder(4096).Decode(headers.Payload.AsSpan(5)).Select(static h => h.Key));
    }

    [Fact]
    public async Task PriorityFramesAndHeadersPriorityFollowTheProfile()
    {
        // Firefox-style: PRIORITY frames on idle streams 3..13, requests start at 15 and depend on one of them.
        var firefoxLike = BuiltInProfiles.OkHttp4Android13 with
        {
            Http2 = new Http2Profile(
                Preface:
                [
                    new Http2SettingsFrame([new Http2Setting(1, 65536), new Http2Setting(4, 131072), new Http2Setting(5, 16384)]),
                    new Http2WindowUpdateFrame(12517377),
                    new Http2PriorityFrame(3, 0, 200, false),
                    new Http2PriorityFrame(5, 0, 100, false),
                    new Http2PriorityFrame(13, 0, 240, false),
                ],
                PseudoHeaderOrder: [PseudoHeader.Method, PseudoHeader.Path, PseudoHeader.Authority, PseudoHeader.Scheme],
                HeadersPriority: new Http2HeadersPriority(13, 41, false)),
        };

        var capture = await CaptureAsync(firefoxLike);

        Assert.Equal("1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,13:0:0:241|m,p,a,s", capture.Akamai);
        var headers = capture.Frames[^1];
        Assert.Equal(15, headers.StreamId);
        Assert.Equal(0x20, headers.Flags & 0x20);
    }

    private static async Task<Capture> CaptureAsync(ClientProfile profile, Action<HttpRequestMessage>? configure = null)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serving = ServeAsync(listener);

        using var client = new HttpClient(new ChameleonHttpMessageHandler(profile));
        using var request = new HttpRequestMessage(HttpMethod.Get, $"http://127.0.0.1:{port}/")
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        configure?.Invoke(request);

        // The server hangs up after the first HEADERS, so the request itself fails.
        await Assert.ThrowsAnyAsync<Exception>(() => client.SendAsync(request, CancellationToken));
        return await serving;
    }

    private static async Task<Capture> ServeAsync(TcpListener listener)
    {
        using var socket = await listener.AcceptTcpClientAsync(CancellationToken);
        var stream = socket.GetStream();
        var magic = new byte[24];
        await stream.ReadExactlyAsync(magic, CancellationToken);

        var frames = new List<Frame>();
        var header = new byte[9];
        do
        {
            await stream.ReadExactlyAsync(header, CancellationToken);
            var payload = new byte[(header[0] << 16) | (header[1] << 8) | header[2]];
            await stream.ReadExactlyAsync(payload, CancellationToken);
            frames.Add(new Frame(header[3], header[4], BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5)) & int.MaxValue, payload));
        }
        while (frames[^1].Type != 1);

        return new Capture(System.Text.Encoding.ASCII.GetString(magic), frames);
    }

    private sealed record Frame(byte Type, byte Flags, int StreamId, byte[] Payload);

    private sealed record Capture(string Magic, List<Frame> Frames)
    {
        /// <summary>Computed independently of <see cref="AkamaiFingerprint"/>, from the captured bytes.</summary>
        public string Akamai
        {
            get
            {
                var settings = Frames.First(static f => f.Type == 4).Payload.Chunk(6)
                    .Select(static s => $"{BinaryPrimitives.ReadUInt16BigEndian(s)}:{BinaryPrimitives.ReadUInt32BigEndian(s.AsSpan(2))}");
                var update = Frames.FirstOrDefault(static f => f.Type == 8) is { } w
                    ? BinaryPrimitives.ReadInt32BigEndian(w.Payload).ToString(CultureInfo.InvariantCulture)
                    : "00";
                var priorities = Frames.Where(static f => f.Type == 2).Select(static f =>
                {
                    var dependency = BinaryPrimitives.ReadUInt32BigEndian(f.Payload);
                    return $"{f.StreamId}:{dependency >> 31}:{dependency & int.MaxValue}:{f.Payload[4] + 1}";
                }).ToList();

                var headers = Frames[^1];
                var block = (headers.Flags & 0x20) != 0 ? headers.Payload[5..] : headers.Payload;
                var pseudo = new HpackDecoder(4096).Decode(block).Where(static h => h.Key.StartsWith(':')).Select(static h => h.Key[1..2]);

                return string.Join('|', string.Join(';', settings), update, priorities.Count == 0 ? "0" : string.Join(',', priorities), string.Join(',', pseudo));
            }
        }
    }
}
