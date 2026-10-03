using System.Buffers.Binary;

namespace Chameleon.Net.Inspector.Tls;

/// <summary>Reads the ClientHello off the socket before the TLS server sees it. The hello may span several records
/// (post-quantum key shares push it past one 16 KiB record for some clients), so records are read until the handshake message is complete.</summary>
internal static class ClientHelloReader
{
    private const byte HandshakeContentType = 22;
    private const int MaxHelloLength = ushort.MaxValue - 4; // fits one synthetic record for ClientHelloParser

    /// <param name="firstByte">Already read to tell TLS from plain HTTP.</param>
    /// <returns>The raw records, to replay to the TLS server, and the reassembled handshake message.</returns>
    /// <exception cref="FormatException">Not a TLS handshake.</exception>
    public static async Task<(byte[] Records, byte[] Handshake, ushort RecordVersion)> ReadAsync(Stream stream, byte firstByte, CancellationToken cancellationToken)
    {
        var records = new List<byte>();
        var handshake = new List<byte>();
        ushort recordVersion = 0;
        var header = new byte[5];
        header[0] = firstByte;
        var headerOffset = 1;

        while (handshake.Count < 4 || handshake.Count < 4 + HandshakeLength(handshake))
        {
            await stream.ReadExactlyAsync(header.AsMemory(headerOffset), cancellationToken);
            headerOffset = 0;
            if (header[0] != HandshakeContentType)
            {
                throw new FormatException($"Expected a handshake record, got content type {header[0]}.");
            }

            var length = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(3));
            if (records.Count == 0)
            {
                recordVersion = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(1));
            }

            var payload = new byte[length];
            await stream.ReadExactlyAsync(payload, cancellationToken);
            records.AddRange(header);
            records.AddRange(payload);
            handshake.AddRange(payload);

            if (handshake.Count >= 4 && (handshake[0] != 1 || HandshakeLength(handshake) > MaxHelloLength))
            {
                throw new FormatException("The first handshake message is not a ClientHello.");
            }
        }

        return ([.. records], [.. handshake.Take(4 + HandshakeLength(handshake))], recordVersion);
    }

    private static int HandshakeLength(List<byte> handshake) => (handshake[1] << 16) | (handshake[2] << 8) | handshake[3];
}
