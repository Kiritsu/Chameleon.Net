using System.Text.Json;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Tests.Http;

/// <summary>Real network. Explicit: run with <c>dotnet test --solution Chameleon.Net.slnx -- --explicit only</c>.</summary>
public sealed class LiveHttpTests
{
    private const string OkHttpJa3 =
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0";

    [Fact(Explicit = true)]
    public async Task CloudflareSeesHttp2OverTls13()
    {
        using var client = new HttpClient(new ChameleonHttpMessageHandler(BuiltInProfiles.OkHttp4Android13));

        var trace = await client.GetStringAsync(new Uri("https://www.cloudflare.com/cdn-cgi/trace"), TestContext.Current.CancellationToken);

        Assert.Contains("http=http/2", trace, StringComparison.Ordinal);
        Assert.Contains("tls=TLSv1.3", trace, StringComparison.Ordinal);
    }

    /// <summary>What tls.peet.ws reported for the real Chromium 152, reproduced by the profile.</summary>
    [Fact(Explicit = true)]
    public async Task EchoServiceSeesTheChromiumCapture()
    {
        var profile = BuiltInProfiles.Chromium152Windows;
        using var client = new HttpClient(new ChameleonHttpMessageHandler(profile));

        using var json = JsonDocument.Parse(await client.GetStringAsync(new Uri("https://tls.peet.ws/api/all"), TestContext.Current.CancellationToken));
        var root = json.RootElement;
        var headers = root.GetProperty("http2").GetProperty("sent_frames").EnumerateArray().Single(static f => f.GetProperty("frame_type").GetString() == "HEADERS");

        Assert.Equal("t13d1516h2_8daaf6152771_806a8c22fdea", root.GetProperty("tls").GetProperty("ja4").GetString());
        Assert.Equal("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", root.GetProperty("http2").GetProperty("akamai_fingerprint").GetString());
        Assert.Equal(220, headers.GetProperty("priority").GetProperty("weight").GetInt32());
        Assert.Equal(1, headers.GetProperty("priority").GetProperty("exclusive").GetInt32());
    }

    [Fact(Explicit = true)]
    public async Task EchoServiceSeesTheFirefoxCapture()
    {
        var profile = BuiltInProfiles.Firefox156Windows;
        using var client = new HttpClient(new ChameleonHttpMessageHandler(profile));

        using var json = JsonDocument.Parse(await client.GetStringAsync(new Uri("https://tls.peet.ws/api/all"), TestContext.Current.CancellationToken));
        var root = json.RootElement;
        var headers = root.GetProperty("http2").GetProperty("sent_frames").EnumerateArray().Single(static f => f.GetProperty("frame_type").GetString() == "HEADERS");

        Assert.Equal("9d42e90b0225e779f03141ddcd699df2", root.GetProperty("tls").GetProperty("ja3_hash").GetString());
        Assert.Equal("t13d1517h2_8daaf6152771_3cbfd9057e0d", root.GetProperty("tls").GetProperty("ja4").GetString());
        Assert.Equal("1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s", root.GetProperty("http2").GetProperty("akamai_fingerprint").GetString());
        Assert.Equal(3, headers.GetProperty("stream_id").GetInt32());
        Assert.Equal(22, headers.GetProperty("priority").GetProperty("weight").GetInt32());
        Assert.Equal(0, headers.GetProperty("priority").GetProperty("exclusive").GetInt32());
    }

    [Fact(Explicit = true)]
    public async Task EchoServiceSeesTheEdgeCapture()
    {
        using var client = new HttpClient(new ChameleonHttpMessageHandler(BuiltInProfiles.Edge153Windows));

        using var json = JsonDocument.Parse(await client.GetStringAsync(new Uri("https://tls.peet.ws/api/all"), TestContext.Current.CancellationToken));
        var root = json.RootElement;
        var headers = root.GetProperty("http2").GetProperty("sent_frames").EnumerateArray().Single(static f => f.GetProperty("frame_type").GetString() == "HEADERS");

        Assert.Equal("t13d1516h2_8daaf6152771_806a8c22fdea", root.GetProperty("tls").GetProperty("ja4").GetString());
        Assert.Equal("1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", root.GetProperty("http2").GetProperty("akamai_fingerprint").GetString());
        Assert.Contains("sec-ch-ua: \"Microsoft Edge\";v=\"153\", \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"153\"",
            headers.GetProperty("headers").EnumerateArray().Select(static h => h.GetString()));
    }

    /// <summary>NSS offers delegated credentials and zstd certificate compression, which we can't process: check big servers don't use them on us.</summary>
    [Theory(Explicit = true)]
    [InlineData("https://www.cloudflare.com/cdn-cgi/trace")]
    [InlineData("https://www.google.com/")]
    [InlineData("https://example.com/")]
    [InlineData("https://www.mozilla.org/")]
    [InlineData("https://github.com/")]
    public async Task FirefoxProfileConnects(string url)
    {
        using var client = new HttpClient(new ChameleonHttpMessageHandler(BuiltInProfiles.Firefox156Windows));

        using var response = await client.GetAsync(new Uri(url), TestContext.Current.CancellationToken);

        Assert.True((int)response.StatusCode < 500, response.StatusCode.ToString());
    }

    /// <summary>The fingerprints as observed by a third party, not by our own parser.</summary>
    [Fact(Explicit = true)]
    public async Task EchoServiceObservesTheProfileFingerprints()
    {
        var profile = BuiltInProfiles.OkHttp4Android13;
        using var client = new HttpClient(new ChameleonHttpMessageHandler(profile));

        using var json = JsonDocument.Parse(await client.GetStringAsync(new Uri("https://tls.peet.ws/api/all"), TestContext.Current.CancellationToken));
        var root = json.RootElement;

        Assert.Equal("h2", root.GetProperty("http_version").GetString());
        Assert.Equal(OkHttpJa3, root.GetProperty("tls").GetProperty("ja3").GetString());
        Assert.StartsWith("t13d1513h2_", root.GetProperty("tls").GetProperty("ja4").GetString(), StringComparison.Ordinal);
        Assert.Equal(AkamaiFingerprint.Compute(profile.Http2), root.GetProperty("http2").GetProperty("akamai_fingerprint").GetString());
    }
}
