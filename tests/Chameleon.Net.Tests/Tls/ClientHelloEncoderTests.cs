using System.Buffers.Binary;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;

namespace Chameleon.Net.Tests.Tls;

/// <summary>Encoder behaviour on a Chrome-shaped profile: GREASE everywhere, per-connection shuffle. No network.</summary>
public sealed class ClientHelloEncoderTests
{
    private const int Connections = 20;

    private static readonly TlsProfile ChromeShaped = new(
        CipherSuites: [4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        Extensions:
        [
            new GreaseExtension(),
            new ServerNameExtension(),
            new ExtendedMasterSecretExtension(),
            new RenegotiationInfoExtension(),
            new SupportedGroupsExtension([29, 23, 24]),
            new EcPointFormatsExtension([0]),
            new SessionTicketExtension(),
            new AlpnExtension(["h2", "http/1.1"]),
            new StatusRequestExtension(),
            new SignatureAlgorithmsExtension([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]),
            new SignedCertificateTimestampExtension(),
            new KeyShareExtension([29]),
            new PskKeyExchangeModesExtension([1]),
            new SupportedVersionsExtension([0x0304, 0x0303]),
            new CompressCertificateExtension([2]),
            new GreaseExtension(new byte[] { 0 }),
            new PaddingExtension(512),
        ],
        Shuffle: ExtensionShufflePolicy.Chrome,
        Grease: GreasePlacement.CipherSuites | GreasePlacement.SupportedGroups | GreasePlacement.KeyShare | GreasePlacement.SupportedVersions);

    [Fact]
    public async Task ShuffleChangesJa3ButNotJa4()
    {
        var fingerprints = new List<TlsFingerprint>();
        for (var i = 0; i < Connections; i++)
        {
            fingerprints.Add(TlsFingerprinter.Compute(await CaptureAsync()));
        }

        Assert.Single(fingerprints.Select(static f => f.Ja4).Distinct());
        Assert.True(fingerprints.Select(static f => f.Ja3).Distinct().Count() > 1, "Chrome shuffle produced the same extension order every time.");
    }

    [Fact]
    public async Task GreaseIsPlacedWhereTheProfileSays()
    {
        for (var i = 0; i < Connections; i++)
        {
            var hello = await CaptureAsync();

            Assert.True(IsGrease(hello.CipherSuites[0]), "cipher suites");
            Assert.True(IsGrease(hello.SupportedGroups[0]), "supported_groups");
            Assert.True(IsGrease(hello.SupportedVersions[0]), "supported_versions");
            Assert.True(IsGrease(hello.ExtensionTypes[0]), "first extension");

            var tail = hello.ExtensionTypes[^1] == 0x0015 ? hello.ExtensionTypes[^2] : hello.ExtensionTypes[^1];
            Assert.True(IsGrease(tail), "last extension before padding");
            Assert.NotEqual(hello.ExtensionTypes[0], tail);
            Assert.Equal(2, hello.ExtensionTypes.Count(IsGrease));
        }
    }

    [Fact]
    public async Task ShuffleKeepsEveryProfileExtension()
    {
        var expected = ChromeShaped.Extensions
            .Where(static e => e is not GreaseExtension and not PaddingExtension)
            .Select(static e => e.Type)
            .Order();

        var hello = await CaptureAsync();

        Assert.Equal(expected, hello.ExtensionTypes.Where(static t => !IsGrease(t) && t != 0x0015).Order());
    }

    [Fact]
    public async Task GreaseBodiesMatchBoringSsl()
    {
        for (var i = 0; i < Connections; i++)
        {
            var grease = RawExtensions(await ClientHelloCapture.CaptureAsync(ChromeShaped, "example.com"))
                .Where(static e => IsGrease(e.Type))
                .ToList();

            Assert.Equal(2, grease.Count);
            Assert.Empty(grease[0].Body);
            Assert.Equal([0], grease[^1].Body);
        }
    }

    private static async Task<ParsedClientHello> CaptureAsync() =>
        ClientHelloParser.Parse(await ClientHelloCapture.CaptureAsync(ChromeShaped, "example.com"));

    // ClientHelloParser keeps only extension types; walk the record by hand to see the bodies.
    private static List<(ushort Type, byte[] Body)> RawExtensions(byte[] record)
    {
        var body = record.AsSpan(5 + 4);
        var offset = 2 + 32;
        offset += 1 + body[offset];
        offset += 2 + BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 1 + body[offset];

        var extensions = body.Slice(offset + 2, BinaryPrimitives.ReadUInt16BigEndian(body[offset..]));
        var result = new List<(ushort, byte[])>();
        while (!extensions.IsEmpty)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(extensions[2..]);
            result.Add((BinaryPrimitives.ReadUInt16BigEndian(extensions), extensions.Slice(4, length).ToArray()));
            extensions = extensions[(4 + length)..];
        }

        return result;
    }

    private static bool IsGrease(ushort value) => (value & 0x0F0F) == 0x0A0A && value >> 8 == (value & 0xFF);
}
