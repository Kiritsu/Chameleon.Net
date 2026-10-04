using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Http;
using Chameleon.Net.Http.Http2.Hpack;
using Chameleon.Net.Inspector.Analysis;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;

namespace Chameleon.Net.Tests.Inspector;

/// <summary>Every built-in profile end to end against the inspector over loopback: the TLS, HTTP/2 and header fingerprints it sees,
/// and the consistency checks a CDN would run. No network.</summary>
public sealed class InspectorTests
{
    private const string ChromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";

    private static readonly X509Certificate2 Certificate = TestCertificates.SelfSigned();

    /// <summary>Every built-in profile, including the ones added by the automated capture.</summary>
    private static readonly Dictionary<string, ClientProfile> Profiles = KnownClients.BuiltIn().ToDictionary(static p => p.Identity.Name);

    /// <summary>JA4 of the real clients, as tls.peet.ws showed them (the hand-verified profiles).</summary>
    private static readonly Dictionary<string, string> BrowserJa4 = new()
    {
        ["chromium_152_windows"] = "t13d1516h2_8daaf6152771_806a8c22fdea",
        ["edge_153_windows"] = "t13d1516h2_8daaf6152771_806a8c22fdea",
        ["firefox_156_windows"] = "t13d1517h2_8daaf6152771_3cbfd9057e0d",
    };

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    /// <summary>Navigations and fetch() for profiles that tell them apart (browsers), fetch() only for the others.</summary>
    public static TheoryData<string, RequestKind> ProfileRequests
    {
        get
        {
            var data = new TheoryData<string, RequestKind>();
            foreach (var profile in Profiles.Values)
            {
                if (profile.Headers.Overrides.ContainsKey(RequestKind.Navigate) || profile.Headers.DefaultHeaderOverrides?.ContainsKey(RequestKind.Navigate) == true)
                {
                    data.Add(profile.Identity.Name, RequestKind.Navigate);
                }

                data.Add(profile.Identity.Name, RequestKind.Fetch);
            }

            return data;
        }
    }

    public static TheoryData<string> ProfileNames => new(Profiles.Keys);

    [Theory]
    [MemberData(nameof(ProfileRequests))]
    public async Task BuiltInProfilesLookLikeTheirClientOverHttp2(string name, RequestKind kind)
    {
        var profile = Profiles[name];
        await using var server = await StartAsync();
        using var client = Client(profile);

        var report = await GetReportAsync(client, new Uri($"https://localhost:{server.Port}/inspect"), kind);

        Assert.Equal("h2", report.Connection.Alpn);
        Assert.Contains(name, report.Client.TlsMatches);
        Assert.Contains(name, report.Client.Http2Matches);
        Assert.Equal(AkamaiFingerprint.Compute(profile.Http2), report.Http!.Http2!.Akamai);
        Assert.Equal((int)profile.Http2.FirstStreamId, report.Http.Http2.FirstStreamId);
        if (BrowserJa4.TryGetValue(name, out var ja4))
        {
            Assert.Equal(ja4, report.Tls!.Ja4);
        }

        Assert.Equal("localhost", report.Tls!.ServerName);
        Assert.Equal(KnownClients.FamilyOf(profile), report.Client.UserAgent!.Family);
        AssertConsistent(report);
    }

    [Theory]
    [MemberData(nameof(ProfileNames))]
    public async Task BuiltInProfilesKeepTheirHeaderCasingOverPlainHttp(string name)
    {
        await using var server = await StartAsync();
        using var client = Client(Profiles[name]);

        var report = await GetReportAsync(client, new Uri($"http://localhost:{server.Port}/plain"), RequestKind.Fetch);

        Assert.False(report.Connection.Tls);
        Assert.Equal("1.1", report.Http!.Version);
        Assert.Contains(report.Http.Headers, static h => h.Name == "User-Agent");
        AssertConsistent(report);
    }

    [Fact]
    public async Task Http2WithPriorKnowledgeIsInspectedOnThePlainPort()
    {
        var profile = BuiltInProfiles.OkHttp4Android13;
        await using var server = await StartAsync();
        using var client = Client(profile);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"http://localhost:{server.Port}/h2c"))
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };

        using var response = await client.SendAsync(request, CancellationToken);
        var report = Deserialize(await response.Content.ReadAsStringAsync(CancellationToken));

        Assert.Equal("2", report.Http!.Version);
        Assert.Equal(AkamaiFingerprint.Compute(profile.Http2), report.Http.Http2!.Akamai);
        Assert.Contains("okhttp4_android_13", report.Client.Http2Matches);
    }

    [Theory]
    [MemberData(nameof(ProfileNames))]
    public async Task WebSocketHandshakesLookLikeTheirClient(string name)
    {
        var profile = Profiles[name];
        await using var server = await StartAsync();
        var connector = new ChameleonWebSocketConnector(new ChameleonOptions { CertificateValidator = new TrustAnyCertificate() });

        using var socket = await connector.ConnectAsync(new Uri($"wss://localhost:{server.Port}/ws"), profile, cancellationToken: CancellationToken);
        var report = Deserialize(await socket.ReceiveTextAsync(CancellationToken));

        Assert.True(report.Http!.WebSocket);
        Assert.Equal("http/1.1", report.Connection.Alpn);
        Assert.Contains(name, report.Client.TlsMatches);
        AssertConsistent(report);
    }

    [Fact]
    public async Task ChromeShufflesItsExtensionsOnEveryConnection()
    {
        await using var server = await StartAsync();

        var reports = new List<InspectionReport>();
        for (var i = 0; i < 3; i++)
        {
            using var client = Client(BuiltInProfiles.Chromium152Windows, resumeSessions: false);
            reports.Add(await GetReportAsync(client, new Uri($"https://localhost:{server.Port}/"), RequestKind.Fetch));
        }

        Assert.Equal(3, reports[^1].Tls!.ExtensionOrder.Connections);
        Assert.True(reports[^1].Tls!.ExtensionOrder.DistinctOrders > 1);
        Assert.Single(reports.Select(static r => r.Tls!.Ja4).Distinct());
        Assert.True(reports.Select(static r => r.Tls!.Ja3Hash).Distinct().Count() > 1);
        Assert.DoesNotContain(reports[^1].Findings, static f => f.Id == "extension-order-fixed");
    }

    [Fact]
    public async Task FirefoxKeepsOneExtensionOrder()
    {
        await using var server = await StartAsync();

        InspectionReport? report = null;
        for (var i = 0; i < 3; i++)
        {
            using var client = Client(BuiltInProfiles.Firefox156Windows, resumeSessions: false);
            report = await GetReportAsync(client, new Uri($"https://localhost:{server.Port}/"), RequestKind.Fetch);
        }

        Assert.Equal(new ExtensionOrderReport(3, 1), report!.Tls!.ExtensionOrder);
        AssertConsistent(report);
    }

    /// <summary>What Chameleon.Net exists to avoid: .NET's own TLS and HTTP/2 under a Chrome User-Agent.</summary>
    [Fact]
    public async Task PlainHttpClientClaimingToBeChromeIsInconsistent()
    {
        await using var server = await StartAsync();
        using var handler = new SocketsHttpHandler();
        handler.SslOptions.RemoteCertificateValidationCallback = static (_, certificate, _, _) => certificate?.GetCertHashString() == Certificate.Thumbprint;
        using var client = new HttpClient(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"https://localhost:{server.Port}/"))
        {
            Version = HttpVersion.Version20,
        };
        request.Headers.TryAddWithoutValidation("User-Agent", ChromeUserAgent);

        using var response = await client.SendAsync(request, CancellationToken);
        var report = Deserialize(await response.Content.ReadAsStringAsync(CancellationToken));

        Assert.Equal(Verdict.Inconsistent, report.Verdict);
        Assert.Equal(ClientFamily.Unknown, report.Client.TlsFamily);
        Assert.Contains(report.Findings, static f => f is { Id: "tls-family", Severity: Severity.High });
        Assert.Contains(report.Findings, static f => f is { Id: "http2-family", Severity: Severity.High });
        Assert.Contains(report.Findings, static f => f.Id == "missing-headers");
    }

    [Fact]
    public async Task ClientHintsThatContradictTheUserAgentAreFlagged()
    {
        await using var server = await StartAsync();
        using var client = Client(BuiltInProfiles.Chromium152Windows);
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"https://localhost:{server.Port}/"));
        request.Headers.TryAddWithoutValidation("sec-ch-ua", "\"Microsoft Edge\";v=\"152\", \"Chromium\";v=\"152\"");
        request.Headers.TryAddWithoutValidation("sec-ch-ua-platform", "\"macOS\"");

        using var response = await client.SendAsync(request, CancellationToken);
        var report = Deserialize(await response.Content.ReadAsStringAsync(CancellationToken));

        Assert.Contains(report.Findings, static f => f.Id == "client-hints-brand");
        Assert.Contains(report.Findings, static f => f.Id == "client-hints-platform");
        Assert.Equal(Verdict.Inconsistent, report.Verdict);
    }

    [Fact]
    public async Task ClientThatRejectsTheCertificateStillGetsItsClientHelloReported()
    {
        await using var server = await StartAsync();
        var reported = new TaskCompletionSource<InspectionReport>(TaskCreationOptions.RunContinuationsAsynchronously);
        server.Inspected += report => reported.TrySetResult(report);
        using var client = new HttpClient(new ChameleonHttpMessageHandler(BuiltInProfiles.OkHttp4Android13));

        await Assert.ThrowsAnyAsync<Exception>(() => client.GetAsync(new Uri($"https://localhost:{server.Port}/"), CancellationToken));
        var report = await reported.Task.WaitAsync(TimeSpan.FromSeconds(10), CancellationToken);

        Assert.Null(report.Http);
        Assert.NotNull(report.Connection.Error);
        Assert.Contains("okhttp4_android_13", report.Client.TlsMatches);
    }

    [Theory]
    [MemberData(nameof(ProfileNames))]
    public async Task BuiltInProfilesSendCookiesOverHttp2LikeTheirClient(string name)
    {
        var profile = Profiles[name];
        await using var server = await StartAsync();
        using var client = Client(profile);
        client.DefaultRequestHeaders.Add("Cookie", "b=2; a=1");

        var report = await GetReportAsync(client, new Uri($"https://localhost:{server.Port}/inspect"), RequestKind.Fetch);

        string[] expected = profile.Http2.Hpack?.SplitCookies == true ? ["b=2", "a=1"] : ["b=2; a=1"];
        Assert.Equal(expected, report.Http!.Headers.Where(static h => h.Name == "cookie").Select(static h => h.Value));
        Assert.All(report.Http.Http2!.Hpack!.Where(static f => f.Name == "cookie"),
            static f => Assert.Equal(HpackRepresentation.IncrementalIndexing, f.Representation));
        AssertConsistent(report);
    }

    [Fact]
    public async Task ChromeUserAgentWithJoinedCookiesIsFlagged()
    {
        var chrome = BuiltInProfiles.Chrome154Windows;
        await using var server = await StartAsync();
        using var client = Client(chrome with { Http2 = chrome.Http2 with { Hpack = null } });
        client.DefaultRequestHeaders.Add("Cookie", "b=2; a=1");

        var report = await GetReportAsync(client, new Uri($"https://localhost:{server.Port}/inspect"), RequestKind.Fetch);

        Assert.Contains(report.Findings, static f => f.Id == "cookies-joined");
    }

    [Fact]
    public async Task ReportsSurviveAJsonRoundTrip()
    {
        await using var server = await StartAsync();
        using var client = Client(BuiltInProfiles.Firefox156Windows);
        client.DefaultRequestHeaders.Referrer = new Uri("https://example.com/");
        client.DefaultRequestHeaders.Add("Cookie", "b=2; a=1");

        var report = await GetReportAsync(client, new Uri($"https://localhost:{server.Port}/"), RequestKind.Fetch);

        // JA4H: GET over HTTP/2 with a cookie and a referer, and cookie names sorted.
        Assert.StartsWith("ge20cr", report.Http!.Ja4H, StringComparison.Ordinal);
        Assert.EndsWith("_a,b_a=1,b=2", report.Http.Ja4HRaw, StringComparison.Ordinal);
        Assert.Contains(report.Tls!.Extensions, static e => e.Name == "delegated_credentials");
        Assert.NotNull(report.Tls.EncryptedClientHello);
    }

    private static async Task<InspectorServer> StartAsync() =>
        await InspectorServer.StartAsync([new IPEndPoint(IPAddress.Loopback, 0), new IPEndPoint(IPAddress.IPv6Loopback, 0)], Certificate);

    private static HttpClient Client(ClientProfile profile, bool resumeSessions = true) => new(new ChameleonHttpMessageHandler(new ChameleonOptions
    {
        ProfileSelector = new FixedProfileSelector(profile),
        CertificateValidator = new TrustAnyCertificate(),
        TlsSessionResumption = resumeSessions,
    }));

    private static async Task<InspectionReport> GetReportAsync(HttpClient client, Uri uri, RequestKind kind)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Options.Set(ChameleonRequestOptions.Kind, kind);
        using var response = await client.SendAsync(request, CancellationToken);
        Assert.Equal(new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" }, response.Content.Headers.ContentType);
        return Deserialize(await response.Content.ReadAsStringAsync(CancellationToken));
    }

    private static InspectionReport Deserialize(string json) => JsonSerializer.Deserialize<InspectionReport>(json, ReportJson.Options)!;

    private static void AssertConsistent(InspectionReport report)
    {
        var serious = report.Findings.Where(static f => f.Severity >= Severity.Medium).Select(static f => $"{f.Id}: {f.Message}").ToList();
        Assert.True(serious.Count == 0, string.Join(Environment.NewLine, serious));
        Assert.Equal(Verdict.Consistent, report.Verdict);
    }
}
