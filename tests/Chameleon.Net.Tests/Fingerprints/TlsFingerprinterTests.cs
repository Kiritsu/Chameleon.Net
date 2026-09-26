using Chameleon.Net.Fingerprints;
using static Chameleon.Net.Tests.Support.ClientHelloBuilder;

namespace Chameleon.Net.Tests.Fingerprints;

public sealed class TlsFingerprinterTests
{
    private static readonly ushort[] FoxIoCiphers =
        [0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca8, 0xcca9];

    [Fact]
    public void Ja4MatchesFoxIoReferenceExample()
    {
        var fingerprint = Compute(FoxIoExample(Alpn("h2")));

        Assert.Equal("t13d1516h2_8daaf6152771_e5627efa2ab1", fingerprint.Ja4);
        Assert.Equal(
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
            + "_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01"
            + "_0403,0804,0401,0503,0805,0501,0806,0601",
            fingerprint.Ja4Raw);
    }

    [Fact]
    public void Ja4IgnoresGreaseEverywhere()
    {
        var plain = Compute(FoxIoExample(Alpn("h2")));
        var greased = Compute(Record(0x0303, [0x3A3A, .. FoxIoCiphers],
        [
            Extension(0x0A0A),
            .. FoxIoExtensions(Alpn("h2"), groups: [0x5A5A, 0x001D], versions: [0x7A7A, 0x0304, 0x0303]),
            Extension(0xFAFA, 0),
        ]));

        Assert.Equal(plain.Ja4, greased.Ja4);
        Assert.Equal(plain.Ja4Raw, greased.Ja4Raw);
    }

    [Fact]
    public void Ja4IsIndependentOfExtensionOrder()
    {
        var ordered = Compute(FoxIoExample(Alpn("h2")));
        var reversed = Compute(Record(0x0303, FoxIoCiphers, [.. FoxIoExtensions(Alpn("h2")).Reverse()]));

        Assert.Equal(ordered.Ja4, reversed.Ja4);
        Assert.NotEqual(ordered.Ja3, reversed.Ja3);
    }

    [Theory]
    [InlineData(new byte[] { (byte)'h', (byte)'2' }, "h2")]
    [InlineData(new byte[] { (byte)'h', (byte)'t', (byte)'t', (byte)'p', (byte)'/', (byte)'1', (byte)'.', (byte)'1' }, "h1")]
    [InlineData(new byte[] { (byte)'h' }, "hh")]
    [InlineData(new byte[] { 0xAB, 0xCD }, "ad")]
    [InlineData(new byte[] { 0x20, 0x61 }, "21")]
    public void AlpnMarkerFollowsFoxIoRules(byte[] firstProtocol, string expected)
    {
        var fingerprint = Compute(FoxIoExample(Alpn(firstProtocol, "x"u8.ToArray())));

        Assert.Equal(expected, fingerprint.Ja4[8..10]);
    }

    [Fact]
    public void AlpnMarkerIsZeroesWithoutAlpn()
    {
        var fingerprint = Compute(Record(0x0303, FoxIoCiphers, Extension(0x0000), Extension(0x002b, SupportedVersions(0x0304))));

        Assert.Equal("t13d150200", fingerprint.Ja4[..10]);
    }

    [Fact]
    public void MissingServerNameMarksIp()
    {
        var fingerprint = Compute(Record(0x0303, FoxIoCiphers, Extension(0x002b, SupportedVersions(0x0304))));

        Assert.Equal('i', fingerprint.Ja4[3]);
    }

    [Fact]
    public void VersionFallsBackToLegacyFieldWithoutSupportedVersions()
    {
        var fingerprint = Compute(Record(0x0303, FoxIoCiphers, Extension(0x0000)));

        Assert.StartsWith("t12d", fingerprint.Ja4, StringComparison.Ordinal);
    }

    [Fact]
    public void Ja3MatchesTlsClientOkHttp4Android13()
    {
        var fingerprint = Compute(Record(0x0303,
            [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
            Extension(0x0000),
            Extension(0x0017),
            Extension(0xff01, 0),
            Extension(0x000a, UInt16List(0x001D, 0x0017, 0x0018)),
            Extension(0x000b, PointFormats(0)),
            Extension(0x0023),
            Extension(0x0010, Alpn("h2", "http/1.1")),
            Extension(0x0005, 1, 0, 0, 0, 0),
            Extension(0x000d, UInt16List(0x0403)),
            Extension(0x0033),
            Extension(0x002d, 1, 1),
            Extension(0x002b, SupportedVersions(0x0304, 0x0303)),
            Extension(0x0015)));

        Assert.Equal(
            "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
            fingerprint.Ja3);
        Assert.Equal("1d714db2228763eab228fc28ce7f8e4f", fingerprint.Ja3Hash);
    }

    [Fact]
    public void TruncatedRecordIsAFormatError()
    {
        var record = FoxIoExample(Alpn("h2"));

        Assert.Throws<FormatException>(() => ClientHelloParser.Parse(record.AsSpan(0, record.Length - 10)));
    }

    [Fact]
    public void InconsistentExtensionLengthIsAFormatError()
    {
        // supported_groups claiming 64 bytes of data but carrying 2.
        var record = Record(0x0303, FoxIoCiphers, new byte[] { 0x00, 0x0A, 0x00, 0x40, 0x00, 0x02 });

        Assert.Throws<FormatException>(() => ClientHelloParser.Parse(record));
    }

    [Fact]
    public void NonHandshakeRecordIsAFormatError()
    {
        Assert.Throws<FormatException>(() => ClientHelloParser.Parse([23, 3, 3, 0, 0]));
    }

    private static TlsFingerprint Compute(byte[] record) => TlsFingerprinter.Compute(ClientHelloParser.Parse(record));

    private static byte[] FoxIoExample(byte[] alpn) => Record(0x0303, FoxIoCiphers, [.. FoxIoExtensions(alpn)]);

    private static IEnumerable<byte[]> FoxIoExtensions(byte[] alpn, ushort[]? groups = null, ushort[]? versions = null) =>
    [
        Extension(0x0000),
        Extension(0x0010, alpn),
        Extension(0x0005),
        Extension(0x000a, UInt16List(groups ?? [0x001D])),
        Extension(0x000b, PointFormats(0)),
        Extension(0x000d, UInt16List(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)),
        Extension(0x0012),
        Extension(0x0015),
        Extension(0x0017),
        Extension(0x001b, 1, 0, 2),
        Extension(0x0023),
        Extension(0x002b, SupportedVersions(versions ?? [0x0304, 0x0303])),
        Extension(0x002d, 1, 1),
        Extension(0x0033),
        Extension(0x4469),
        Extension(0xff01, 0),
    ];
}
