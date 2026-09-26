using Chameleon.Net.Fingerprints;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;

namespace Chameleon.Net.Tests.Tls;

/// <summary>The built-in profile, pushed through the real BouncyCastle pipeline, must produce the fingerprint published for okhttp4_android_13.</summary>
public sealed class OkHttp4Android13GoldenTests
{
    private static readonly TlsProfile Profile = BuiltInProfiles.OkHttp4Android13.Tls;

    [Fact]
    public async Task EmitsPublishedJa3()
    {
        var fingerprint = await FingerprintAsync("example.com");

        Assert.Equal(
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
            fingerprint.Ja3);
        Assert.Equal("1d714db2228763eab228fc28ce7f8e4f", fingerprint.Ja3Hash);
    }

    [Fact]
    public async Task EmitsJa4DerivedFromProfileData()
    {
        var fingerprint = await FingerprintAsync("example.com");

        Assert.Equal(
            "t13d1513h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
            + "_0005,000a,000b,000d,0015,0017,0023,002b,002d,0033,ff01"
            + "_0403,0804,0401,0503,0805,0501,0806,0601,0201",
            fingerprint.Ja4Raw);
    }

    [Fact]
    public async Task PadsHandshakeToBoringSslTarget()
    {
        var record = await ClientHelloCapture.CaptureAsync(Profile, "example.com");

        var handshakeLength = (record[3] << 8) | record[4];
        Assert.Equal(512, handshakeLength);
    }

    [Fact]
    public async Task OmitsPaddingWhenHelloAlreadyExceedsTarget()
    {
        var oversized = Profile with
        {
            Extensions = [.. Profile.Extensions.SkipLast(1), new RawExtension(0xFE01, new byte[300]), Profile.Extensions[^1]],
        };

        var hello = ClientHelloParser.Parse(await ClientHelloCapture.CaptureAsync(oversized, "example.com"));

        Assert.DoesNotContain((ushort)0x0015, hello.ExtensionTypes);
    }

    [Fact]
    public async Task OmitsPaddingWhenHelloIsBelowPaddingWindow()
    {
        var minimal = new TlsProfile(
            CipherSuites: [0xC02F],
            Extensions:
            [
                new ServerNameExtension(),
                new SupportedGroupsExtension([29]),
                new EcPointFormatsExtension([0]),
                new SignatureAlgorithmsExtension([0x0401]),
                new PaddingExtension(512),
            ],
            Shuffle: ExtensionShufflePolicy.None,
            Grease: GreasePlacement.None);

        var record = await ClientHelloCapture.CaptureAsync(minimal, "example.com");
        var hello = ClientHelloParser.Parse(record);

        Assert.True(((record[3] << 8) | record[4]) <= 0xFF);
        Assert.DoesNotContain((ushort)0x0015, hello.ExtensionTypes);
    }

    [Fact]
    public async Task WebSocketAlpnOverrideChangesOnlyAlpnMarker()
    {
        var webSocketTls = Profile with
        {
            Extensions = [.. Profile.Extensions.Select(e => e is AlpnExtension ? new AlpnExtension(BuiltInProfiles.OkHttp4Android13.WebSocket.Alpn!) : e)],
        };

        var http = await FingerprintAsync("example.com");
        var webSocket = TlsFingerprinter.Compute(ClientHelloParser.Parse(await ClientHelloCapture.CaptureAsync(webSocketTls, "example.com")));

        Assert.Equal("h1", webSocket.Ja4[8..10]);
        Assert.Equal(http.Ja4[10..], webSocket.Ja4[10..]);
    }

    [Theory]
    [InlineData("203.0.113.7")]
    [InlineData("2001:db8::1")]
    public async Task IpLiteralHostsGetNoServerName(string host)
    {
        var hello = ClientHelloParser.Parse(await ClientHelloCapture.CaptureAsync(Profile, host));

        Assert.False(hello.HasServerName);
        Assert.DoesNotContain((ushort)0x0000, hello.ExtensionTypes);
        Assert.Equal('i', TlsFingerprinter.Compute(hello).Ja4[3]);
    }

    private static async Task<TlsFingerprint> FingerprintAsync(string host) =>
        TlsFingerprinter.Compute(ClientHelloParser.Parse(await ClientHelloCapture.CaptureAsync(Profile, host)));
}
