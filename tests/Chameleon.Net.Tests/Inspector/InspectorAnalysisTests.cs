using System.Net;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Inspector.Analysis;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Tests.Inspector;

public sealed class InspectorAnalysisTests
{
    private const string FirefoxUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0";

    /// <summary>An HTTP/2 request from a client with the profile's preface and User-Agent, carrying these cookie fields.</summary>
    private static async Task<InspectionReport> BuildHttp2Async(ClientProfile profile, string[] cookies)
    {
        var builder = new ReportBuilder(await KnownClients.CreateAsync());
        var connection = new ConnectionCapture(1, new IPEndPoint(IPAddress.Loopback, 50000))
        {
            Http2 = new Http2ConnectionCapture(AkamaiFingerprint.Compute(profile.Http2), [], (int)profile.Http2.FirstStreamId, profile.Http2.Preface,
                [":method", ":authority", ":scheme", ":path"]),
        };
        var request = new RequestCapture("2", "GET", "/", "example.com",
            [new HeaderField("user-agent", profile.Headers.DefaultHeaders["User-Agent"]), .. cookies.Select(static c => new HeaderField("cookie", c))],
            [":method", ":authority", ":scheme", ":path"], WebSocket: false, StreamId: (int)profile.Http2.FirstStreamId);

        return builder.Build(connection, request);
    }

    [Theory]
    [InlineData("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/140.0 Mobile/15E148 Safari/605.1.15",
        "Firefox (iOS)", "Safari", 140, "iOS", true)]
    [InlineData("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0",
        "Edge", "Chromium", 153, "Windows", false)]
    [InlineData("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36",
        "Chrome", "Chromium", 152, "Android", true)]
    [InlineData("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        "Safari", "Safari", 18, "macOS", false)]
    [InlineData(FirefoxUserAgent, "Firefox", "Firefox", 156, "Windows", false)]
    [InlineData("okhttp/4.12.0", "OkHttp", "OkHttp", 4, null, false)]
    [InlineData("python-requests/2.32.3", "python-requests", "Tool", 2, null, false)]
    public void UserAgentNamesTheStackUnderneath(string userAgent, string product, string family, int version, string? platform, bool mobile)
    {
        var parsed = UserAgentParser.Parse(userAgent)!;

        Assert.Equal(product, parsed.Product);
        Assert.Equal(Enum.Parse<ClientFamily>(family), parsed.Family);
        Assert.Equal(version, parsed.MajorVersion);
        Assert.Equal(platform, parsed.Platform);
        Assert.Equal(mobile, parsed.Mobile);
    }

    [Fact]
    public async Task HeadersOutOfTheClaimedBrowsersOrderOrCasingAreFlagged()
    {
        var builder = new ReportBuilder(await KnownClients.CreateAsync());
        var request = new RequestCapture("1.1", "GET", "/", "example.com",
        [
            new HeaderField("host", "example.com"),
            new HeaderField("Accept-Language", "en-US,en;q=0.5"),
            new HeaderField("User-Agent", FirefoxUserAgent),
            new HeaderField("Accept", "*/*"),
            new HeaderField("Accept-Encoding", "gzip"),
        ], [], WebSocket: false);

        var report = builder.Build(new ConnectionCapture(1, new IPEndPoint(IPAddress.Loopback, 50000)), request);

        Assert.Contains(report.Findings, static f => f.Id == "header-order" && f.Message.Contains("'Accept-Language' came before 'User-Agent'", StringComparison.Ordinal));
        Assert.Contains(report.Findings, static f => f.Id == "header-casing" && f.Message.Contains("'host' (expected 'Host')", StringComparison.Ordinal));
        Assert.Contains(report.Findings, static f => f.Id == "accept-encoding");
        Assert.Equal(Verdict.Suspicious, report.Verdict);
    }

    [Fact]
    public async Task ChromeCookiesGroupedInOneOfSeveralFieldsAreFlagged()
    {
        var report = await BuildHttp2Async(BuiltInProfiles.Chrome154Windows, ["a=1; b=2", "c=3"]);

        Assert.Contains(report.Findings, static f => f.Id == "cookies-joined");
    }

    [Fact]
    public async Task CookiesAreNotJudgedAgainstAProfileWhoseHpackWasNeverCaptured()
    {
        Assert.Null(BuiltInProfiles.Firefox157Windows.Http2.Hpack);

        var report = await BuildHttp2Async(BuiltInProfiles.Firefox157Windows, ["a=1", "b=2"]);

        Assert.DoesNotContain(report.Findings, static f => f.Id is "cookies-split" or "cookies-joined" or "hpack-representation");
    }

    [Fact]
    public async Task MissingUserAgentIsInconsistent()
    {
        var builder = new ReportBuilder(await KnownClients.CreateAsync());
        var request = new RequestCapture("1.1", "GET", "/", "example.com", [new HeaderField("Host", "example.com")], [], WebSocket: false);

        var report = builder.Build(new ConnectionCapture(1, new IPEndPoint(IPAddress.Loopback, 50000)), request);

        Assert.Equal("user-agent-missing", Assert.Single(report.Findings).Id);
        Assert.Equal(Verdict.Inconsistent, report.Verdict);
    }

    [Fact]
    public void Ja4HHashesHeaderNamesInOrderAndSortsCookies()
    {
        var (hashed, raw) = Ja4H.Compute("POST", "2",
        [
            new HeaderField("user-agent", "x"),
            new HeaderField("cookie", "b=2; a=1"),
            new HeaderField("accept-language", "fr-CH, fr;q=0.9"),
            new HeaderField("referer", "https://example.com/"),
        ]);

        Assert.Equal("po20cr02frch_user-agent,accept-language_a,b_a=1,b=2", raw);
        Assert.StartsWith("po20cr02frch_", hashed, StringComparison.Ordinal);
        Assert.Equal(4, hashed.Split('_').Length);
    }
}
