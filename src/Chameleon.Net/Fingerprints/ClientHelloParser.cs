using System.Buffers.Binary;
using System.Text;

namespace Chameleon.Net.Fingerprints;

/// <summary>Reads a single TLS record containing a ClientHello (record header + handshake header + body), as captured off the wire.</summary>
public static class ClientHelloParser
{
    private const byte HandshakeContentType = 22;
    private const byte ClientHelloHandshakeType = 1;

    /// <exception cref="FormatException">The bytes are not a well-formed ClientHello record.</exception>
    public static ParsedClientHello Parse(ReadOnlySpan<byte> tlsRecord)
    {
        try
        {
            return ParseRecord(tlsRecord);
        }
        catch (Exception exception) when (exception is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            throw new FormatException("ClientHello is truncated or its length fields are inconsistent.", exception);
        }
    }

    private static ParsedClientHello ParseRecord(ReadOnlySpan<byte> tlsRecord)
    {
        if (tlsRecord.Length < 5 || tlsRecord[0] != HandshakeContentType)
        {
            throw new FormatException("Not a TLS handshake record.");
        }

        var recordVersion = ReadUInt16(tlsRecord, 1);
        var handshake = tlsRecord.Slice(5, ReadUInt16(tlsRecord, 3));
        if (handshake.Length < 4 || handshake[0] != ClientHelloHandshakeType)
        {
            throw new FormatException("Not a ClientHello handshake message.");
        }

        var body = handshake.Slice(4, (handshake[1] << 16) | (handshake[2] << 8) | handshake[3]);

        var offset = 0;
        var handshakeVersion = ReadUInt16(body, offset);
        offset += 2 + 32; // version, client random
        offset += 1 + body[offset]; // session id

        var cipherSuitesLength = ReadUInt16(body, offset);
        offset += 2;
        var cipherSuites = ReadUInt16Values(body.Slice(offset, cipherSuitesLength));
        offset += cipherSuitesLength;
        offset += 1 + body[offset]; // compression methods

        var extensionTypes = new List<ushort>();
        IReadOnlyList<ushort> supportedGroups = [];
        IReadOnlyList<byte> ecPointFormats = [];
        IReadOnlyList<ushort> signatureAlgorithms = [];
        IReadOnlyList<ushort> supportedVersions = [];
        IReadOnlyList<string> alpn = [];
        var hasServerName = false;

        if (offset < body.Length)
        {
            var extensions = body.Slice(offset + 2, ReadUInt16(body, offset));
            while (!extensions.IsEmpty)
            {
                var type = ReadUInt16(extensions, 0);
                var data = extensions.Slice(4, ReadUInt16(extensions, 2));
                extensionTypes.Add(type);

                switch (type)
                {
                    case 0x0000:
                        hasServerName = true;
                        break;
                    case 0x000A:
                        supportedGroups = ReadUInt16Values(data.Slice(2, ReadUInt16(data, 0)));
                        break;
                    case 0x000B:
                        ecPointFormats = data.Slice(1, data[0]).ToArray();
                        break;
                    case 0x000D:
                        signatureAlgorithms = ReadUInt16Values(data.Slice(2, ReadUInt16(data, 0)));
                        break;
                    case 0x0010:
                        alpn = ReadAlpnList(data.Slice(2, ReadUInt16(data, 0)));
                        break;
                    case 0x002B:
                        supportedVersions = ReadUInt16Values(data.Slice(1, data[0]));
                        break;
                }

                extensions = extensions[(4 + data.Length)..];
            }
        }

        return new ParsedClientHello(
            recordVersion,
            handshakeVersion,
            cipherSuites,
            extensionTypes,
            supportedGroups,
            ecPointFormats,
            signatureAlgorithms,
            supportedVersions,
            alpn,
            hasServerName);
    }

    private static ushort[] ReadUInt16Values(ReadOnlySpan<byte> list)
    {
        var values = new ushort[list.Length / 2];
        for (var i = 0; i < values.Length; i++)
        {
            values[i] = ReadUInt16(list, i * 2);
        }

        return values;
    }

    private static List<string> ReadAlpnList(ReadOnlySpan<byte> list)
    {
        var protocols = new List<string>();
        while (!list.IsEmpty)
        {
            var protocol = list.Slice(1, list[0]);
            // Latin-1 maps each byte to one char, so non-ASCII protocol ids survive a round trip.
            protocols.Add(Encoding.Latin1.GetString(protocol));
            list = list[(1 + protocol.Length)..];
        }

        return protocols;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> span, int offset) => BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
}
