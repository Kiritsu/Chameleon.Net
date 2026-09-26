using Chameleon.Net.Http;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Tests.Tls;

/// <summary>Every ClientHello feature a Chromium browser uses, against real servers. Real network, explicit.</summary>
public sealed class ChromeShapedLiveTests
{
    internal static readonly TlsProfile ChromeShapedTls = new(
        CipherSuites: [4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        Extensions:
        [
            new GreaseExtension(),
            new ServerNameExtension(),
            new ExtendedMasterSecretExtension(),
            new RenegotiationInfoExtension(),
            new SupportedGroupsExtension([0x11EC, 29, 23, 24]),
            new EcPointFormatsExtension([0]),
            new SessionTicketExtension(),
            new AlpnExtension(["h2", "http/1.1"]),
            new StatusRequestExtension(),
            new SignatureAlgorithmsExtension([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]),
            new SignedCertificateTimestampExtension(),
            new KeyShareExtension([0x11EC, 29]),
            new PskKeyExchangeModesExtension([1]),
            new SupportedVersionsExtension([0x0304, 0x0303]),
            new CompressCertificateExtension([2]),
            new ApplicationSettingsExtension(["h2"]),
            new EncryptedClientHelloGreaseExtension(),
            new GreaseExtension(new byte[] { 0 }),
        ],
        Shuffle: ExtensionShufflePolicy.Chrome,
        Grease: GreasePlacement.CipherSuites | GreasePlacement.SupportedGroups | GreasePlacement.KeyShare | GreasePlacement.SupportedVersions);

    [Theory(Explicit = true)]
    [InlineData("https://www.cloudflare.com/cdn-cgi/trace")]
    [InlineData("https://www.google.com/")]
    [InlineData("https://tls.peet.ws/api/clean")]
    [InlineData("https://example.com/")]
    public async Task ChromeShapedHelloCompletesHandshakes(string url)
    {
        var profile = BuiltInProfiles.OkHttp4Android13 with { Tls = ChromeShapedTls };
        using var client = new HttpClient(new ChameleonHttpMessageHandler(profile));

        for (var attempt = 0; attempt < 3; attempt++)
        {
            // New connection each time: the shuffle and GREASE values change per connection.
            using var fresh = new HttpClient(new ChameleonHttpMessageHandler(profile));
            using var response = await fresh.GetAsync(new Uri(url), TestContext.Current.CancellationToken);
            Assert.True(response.IsSuccessStatusCode, $"{url}: {(int)response.StatusCode}");
        }
    }
}
