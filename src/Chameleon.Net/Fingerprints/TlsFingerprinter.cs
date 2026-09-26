using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Chameleon.Net.Fingerprints;

/// <summary>JA3 (Salesforce) and JA4 (FoxIO) computed from a parsed ClientHello.
/// JA4 field layout: [protocol][version][sni][cipher_count][ext_count][alpn]_[cipher_hash]_[extension+sigalg_hash].
/// <see cref="TlsFingerprint.Ja4Raw"/> is JA4_r: the same fields unhashed, ciphers/extensions sorted, signature algorithms in original order.
/// Both JA4 forms are stable under Chrome's per-connection extension shuffle; JA3 is not.</summary>
public static class TlsFingerprinter
{
    private const ushort ServerNameExtension = 0x0000;
    private const ushort AlpnExtension = 0x0010;

    public static TlsFingerprint Compute(ParsedClientHello hello)
    {
        ArgumentNullException.ThrowIfNull(hello);

        var (ja3Text, ja3Hash) = ComputeJa3(hello);
        var (ja4, ja4Raw) = ComputeJa4(hello);
        return new TlsFingerprint(ja3Text, ja3Hash, ja4, ja4Raw);
    }

    private static (string Text, string Hash) ComputeJa3(ParsedClientHello hello)
    {
        var ciphers = hello.CipherSuites.Where(static c => !GreaseValues.Contains(c));
        var extensions = hello.ExtensionTypes.Where(static e => !GreaseValues.Contains(e));
        var groups = hello.SupportedGroups.Where(static g => !GreaseValues.Contains(g));

        var text = string.Join(",",
            hello.HandshakeVersion,
            string.Join("-", ciphers),
            string.Join("-", extensions),
            string.Join("-", groups),
            string.Join("-", hello.EcPointFormats));

#pragma warning disable CA5351 // MD5 is the JA3 spec, not a security use.
        var hash = Convert.ToHexStringLower(MD5.HashData(Encoding.ASCII.GetBytes(text)));
#pragma warning restore CA5351
        return (text, hash);
    }

    private static (string Standard, string Raw) ComputeJa4(ParsedClientHello hello)
    {
        var prefix = ComputePrefix(hello);

        var cipherHex = hello.CipherSuites.Where(static c => !GreaseValues.Contains(c)).Select(ToHex4)
            .OrderBy(static hex => hex, StringComparer.Ordinal).ToList();
        var extensionHex = hello.ExtensionTypes
            .Where(static e => !GreaseValues.Contains(e) && e != ServerNameExtension && e != AlpnExtension)
            .Select(ToHex4).OrderBy(static hex => hex, StringComparer.Ordinal).ToList();
        var signatureAlgorithmHex = hello.SignatureAlgorithms.Where(static s => !GreaseValues.Contains(s)).Select(ToHex4).ToList();

        var cipherList = string.Join(",", cipherHex);
        var extensionList = string.Join(",", extensionHex);
        var signatureAlgorithmList = string.Join(",", signatureAlgorithmHex);

        var cipherHash = cipherHex.Count == 0 ? "000000000000" : HashHex(cipherList);
        var extensionHash = extensionHex.Count == 0
            ? "000000000000"
            : HashHex(signatureAlgorithmHex.Count == 0 ? extensionList : $"{extensionList}_{signatureAlgorithmList}");

        var standard = $"{prefix}_{cipherHash}_{extensionHash}";
        var raw = signatureAlgorithmHex.Count == 0
            ? $"{prefix}_{cipherList}_{extensionList}"
            : $"{prefix}_{cipherList}_{extensionList}_{signatureAlgorithmList}";

        return (standard, raw);
    }

    private static string ComputePrefix(ParsedClientHello hello)
    {
        var version = SelectVersion(hello);
        var sni = hello.HasServerName ? 'd' : 'i';
        var cipherCount = Math.Min(99, hello.CipherSuites.Count(static c => !GreaseValues.Contains(c)));
        var extensionCount = Math.Min(99, hello.ExtensionTypes.Count(static e => !GreaseValues.Contains(e)));
        var alpn = SelectAlpnMarker(hello);
        return $"t{version}{sni}{cipherCount:D2}{extensionCount:D2}{alpn}";
    }

    private static string SelectVersion(ParsedClientHello hello)
    {
        var candidates = hello.SupportedVersions.Where(static v => !GreaseValues.Contains(v)).ToList();
        var version = candidates.Count > 0 ? candidates.Max() : hello.HandshakeVersion;
        return version switch
        {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            0x0300 => "s3",
            0x0002 => "s2",
            _ => "00",
        };
    }

    // Both first and last byte must be alphanumeric to use their literal characters; otherwise both positions
    // fall back to the hex representation of that byte (first char of hex(first byte), last char of hex(last byte)).
    private static string SelectAlpnMarker(ParsedClientHello hello)
    {
        if (hello.Alpn.Count == 0 || hello.Alpn[0].Length == 0)
        {
            return "00";
        }

        var bytes = Encoding.Latin1.GetBytes(hello.Alpn[0]);
        var first = bytes[0];
        var last = bytes[^1];

        if (IsAlphanumeric(first) && IsAlphanumeric(last))
        {
            return $"{(char)first}{(char)last}";
        }

        return $"{ToHex(first)[0]}{ToHex(last)[1]}";
    }

    private static bool IsAlphanumeric(byte value) =>
        value is >= (byte)'0' and <= (byte)'9' or >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z';

    private static string HashHex(string input) => Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(input)))[..12];

    private static string ToHex4(ushort value) => value.ToString("x4", CultureInfo.InvariantCulture);

    private static string ToHex(byte value) => value.ToString("x2", CultureInfo.InvariantCulture);
}
