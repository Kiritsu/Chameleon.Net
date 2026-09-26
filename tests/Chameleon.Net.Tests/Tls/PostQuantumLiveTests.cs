using Chameleon.Net.Http;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Tests.Tls;

/// <summary>Real network. Explicit: run with <c>dotnet test --solution Chameleon.Net.slnx -- --explicit only</c>.</summary>
public sealed class PostQuantumLiveTests
{
    [Fact(Explicit = true)]
    public async Task CloudflareNegotiatesX25519MlKem768()
    {
        var profile = WithKeyShares(BuiltInProfiles.OkHttp4Android13, groups: [0x11EC, 29, 23, 24], keyShares: [0x11EC, 29]);
        using var client = new HttpClient(new ChameleonHttpMessageHandler(profile));

        var trace = await client.GetStringAsync(new Uri("https://www.cloudflare.com/cdn-cgi/trace"), TestContext.Current.CancellationToken);

        Assert.Contains("kex=X25519MLKEM768", trace, StringComparison.Ordinal);
    }

    [Fact(Explicit = true)]
    public async Task ClassicalShareStillWorksWhenTheServerPrefersIt()
    {
        var profile = WithKeyShares(BuiltInProfiles.OkHttp4Android13, groups: [0x11EC, 29, 23, 24], keyShares: [0x11EC, 29]);
        using var client = new HttpClient(new ChameleonHttpMessageHandler(profile));

        var body = await client.GetStringAsync(new Uri("https://example.com/"), TestContext.Current.CancellationToken);

        Assert.Contains("Example Domain", body, StringComparison.Ordinal);
    }

    /// <summary>Cloudflare answers <c>compress_certificate</c> with a brotli CompressedCertificate; BouncyCastle alone rejects it.</summary>
    [Theory(Explicit = true)]
    [InlineData("https://www.cloudflare.com/cdn-cgi/trace")]
    [InlineData("https://www.google.com/")]
    public async Task CompressedCertificatesAreAccepted(string url)
    {
        var profile = BuiltInProfiles.OkHttp4Android13 with
        {
            Tls = BuiltInProfiles.OkHttp4Android13.Tls with
            {
                Extensions = [.. BuiltInProfiles.OkHttp4Android13.Tls.Extensions.SkipLast(1), new CompressCertificateExtension([2]), BuiltInProfiles.OkHttp4Android13.Tls.Extensions[^1]],
            },
        };
        using var client = new HttpClient(new ChameleonHttpMessageHandler(profile));

        using var response = await client.GetAsync(new Uri(url), TestContext.Current.CancellationToken);

        Assert.True(response.IsSuccessStatusCode);
    }

    internal static ClientProfile WithKeyShares(ClientProfile profile, ushort[] groups, ushort[] keyShares) => profile with
    {
        Tls = profile.Tls with
        {
            Extensions =
            [
                .. profile.Tls.Extensions.Select(extension => extension switch
                {
                    SupportedGroupsExtension => new SupportedGroupsExtension(groups),
                    KeyShareExtension => new KeyShareExtension(keyShares),
                    _ => extension,
                }),
            ],
        },
    };
}
