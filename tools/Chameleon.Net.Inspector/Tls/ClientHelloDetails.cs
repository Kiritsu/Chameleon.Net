using System.Buffers.Binary;
using System.Text;

namespace Chameleon.Net.Inspector.Tls;

internal readonly record struct TlsExtensionEntry(ushort Type, byte[] Data);

internal readonly record struct KeyShareEntry(ushort Group, int Length);

/// <summary>ECH outer extension (type 0): GREASE and real ECH look the same to a server without the matching config.</summary>
internal sealed record EchOffer(ushort Kdf, ushort Aead, byte ConfigId, int EncLength, int PayloadLength);

internal sealed record PskOffer(IReadOnlyList<int> IdentityLengths, int Binders);

/// <summary>Every field of a ClientHello that fingerprinting reads, parsed independently of the library's encoder.</summary>
internal sealed class ClientHelloDetails
{
    public const ushort ServerNameType = 0;
    public const ushort AlpnType = 16;
    public const ushort PaddingType = 21;
    public const ushort PreSharedKeyType = 41;
    public const ushort EarlyDataType = 42;

    public required ushort LegacyVersion { get; init; }
    public required int SessionIdLength { get; init; }
    public required IReadOnlyList<ushort> CipherSuites { get; init; }
    public required IReadOnlyList<TlsExtensionEntry> Extensions { get; init; }
    public string? ServerName { get; private set; }
    public IReadOnlyList<string> Alpn { get; private set; } = [];
    public IReadOnlyList<ushort> SupportedGroups { get; private set; } = [];
    public IReadOnlyList<KeyShareEntry> KeyShares { get; private set; } = [];
    public IReadOnlyList<ushort> SignatureAlgorithms { get; private set; } = [];
    public IReadOnlyList<ushort> SupportedVersions { get; private set; } = [];
    public IReadOnlyList<byte> EcPointFormats { get; private set; } = [];
    public IReadOnlyList<byte> PskKeyExchangeModes { get; private set; } = [];
    public IReadOnlyList<ushort> CertificateCompression { get; private set; } = [];
    public IReadOnlyList<ushort> DelegatedCredentials { get; private set; } = [];
    public ushort? AlpsCodepoint { get; private set; }
    public IReadOnlyList<string> AlpsProtocols { get; private set; } = [];
    public EchOffer? Ech { get; private set; }
    public int? RecordSizeLimit { get; private set; }
    public int? PaddingLength { get; private set; }
    public PskOffer? PreSharedKey { get; private set; }
    public bool EarlyData { get; private set; }

    public IEnumerable<ushort> ExtensionTypes => Extensions.Select(static e => e.Type);

    public bool HasExtension(ushort type) => Extensions.Any(e => e.Type == type);

    /// <param name="handshake">The ClientHello handshake message: type (1), 3-byte length, body.</param>
    /// <exception cref="FormatException">Not a well-formed ClientHello.</exception>
    public static ClientHelloDetails Parse(ReadOnlySpan<byte> handshake)
    {
        try
        {
            return ParseMessage(handshake);
        }
        catch (Exception exception) when (exception is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            throw new FormatException("ClientHello is truncated or its length fields are inconsistent.", exception);
        }
    }

    private static ClientHelloDetails ParseMessage(ReadOnlySpan<byte> handshake)
    {
        if (handshake.Length < 4 || handshake[0] != 1)
        {
            throw new FormatException("Not a ClientHello handshake message.");
        }

        var body = handshake.Slice(4, (handshake[1] << 16) | (handshake[2] << 8) | handshake[3]);
        var legacyVersion = U16(body, 0);
        var offset = 2 + 32;
        var sessionIdLength = body[offset];
        offset += 1 + sessionIdLength;
        var cipherSuites = U16List(body.Slice(offset + 2, U16(body, offset)));
        offset += 2 + cipherSuites.Length * 2;
        offset += 1 + body[offset]; // compression methods

        var extensions = new List<TlsExtensionEntry>();
        if (offset < body.Length)
        {
            var list = body.Slice(offset + 2, U16(body, offset));
            while (!list.IsEmpty)
            {
                var data = list.Slice(4, U16(list, 2));
                extensions.Add(new TlsExtensionEntry(U16(list, 0), data.ToArray()));
                list = list[(4 + data.Length)..];
            }
        }

        var details = new ClientHelloDetails
        {
            LegacyVersion = legacyVersion,
            SessionIdLength = sessionIdLength,
            CipherSuites = cipherSuites,
            Extensions = extensions,
        };

        foreach (var extension in extensions)
        {
            details.ReadExtension(extension.Type, extension.Data);
        }

        return details;
    }

    private void ReadExtension(ushort type, ReadOnlySpan<byte> data)
    {
        switch (type)
        {
            case ServerNameType when data.Length > 5 && data[2] == 0:
                ServerName = Encoding.ASCII.GetString(data.Slice(5, U16(data, 3)));
                break;
            case 10:
                SupportedGroups = U16List(data.Slice(2, U16(data, 0)));
                break;
            case 11:
                EcPointFormats = data.Slice(1, data[0]).ToArray();
                break;
            case 13:
                SignatureAlgorithms = U16List(data.Slice(2, U16(data, 0)));
                break;
            case AlpnType:
                Alpn = Strings(data.Slice(2, U16(data, 0)));
                break;
            case PaddingType:
                PaddingLength = data.Length;
                break;
            case 27:
                CertificateCompression = U16List(data.Slice(1, data[0]));
                break;
            case 28:
                RecordSizeLimit = U16(data, 0);
                break;
            case 34:
                DelegatedCredentials = U16List(data.Slice(2, U16(data, 0)));
                break;
            case PreSharedKeyType:
                PreSharedKey = ReadPsk(data);
                break;
            case EarlyDataType:
                EarlyData = true;
                break;
            case 43:
                SupportedVersions = U16List(data.Slice(1, data[0]));
                break;
            case 45:
                PskKeyExchangeModes = data.Slice(1, data[0]).ToArray();
                break;
            case 51:
                KeyShares = ReadKeyShares(data.Slice(2, U16(data, 0)));
                break;
            case 17513 or 17613:
                AlpsCodepoint = type;
                AlpsProtocols = Strings(data.Slice(2, U16(data, 0)));
                break;
            case 0xFE0D when data.Length > 0 && data[0] == 0:
                var encLength = U16(data, 6);
                Ech = new EchOffer(U16(data, 1), U16(data, 3), data[5], encLength, U16(data, 8 + encLength));
                break;
        }
    }

    private static PskOffer ReadPsk(ReadOnlySpan<byte> data)
    {
        var identities = data.Slice(2, U16(data, 0));
        var lengths = new List<int>();
        while (!identities.IsEmpty)
        {
            var length = U16(identities, 0);
            lengths.Add(length);
            identities = identities[(2 + length + 4)..]; // identity, obfuscated_ticket_age
        }

        var binders = data[(2 + U16(data, 0) + 2)..];
        var count = 0;
        while (!binders.IsEmpty)
        {
            binders = binders[(1 + binders[0])..];
            count++;
        }

        return new PskOffer(lengths, count);
    }

    private static List<KeyShareEntry> ReadKeyShares(ReadOnlySpan<byte> list)
    {
        var shares = new List<KeyShareEntry>();
        while (!list.IsEmpty)
        {
            var length = U16(list, 2);
            shares.Add(new KeyShareEntry(U16(list, 0), length));
            list = list[(4 + length)..];
        }

        return shares;
    }

    private static List<string> Strings(ReadOnlySpan<byte> list)
    {
        var values = new List<string>();
        while (!list.IsEmpty)
        {
            values.Add(Encoding.Latin1.GetString(list.Slice(1, list[0])));
            list = list[(1 + list[0])..];
        }

        return values;
    }

    private static ushort[] U16List(ReadOnlySpan<byte> list)
    {
        var values = new ushort[list.Length / 2];
        for (var i = 0; i < values.Length; i++)
        {
            values[i] = U16(list, i * 2);
        }

        return values;
    }

    private static ushort U16(ReadOnlySpan<byte> span, int offset) => BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
}
