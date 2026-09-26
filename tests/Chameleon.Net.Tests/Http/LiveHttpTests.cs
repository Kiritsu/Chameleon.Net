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
