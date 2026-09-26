using System.Buffers.Binary;
using System.IO.Compression;
using Org.BouncyCastle.Tls;

namespace Chameleon.Net.Tls;

/// <summary>RFC 8879 CompressedCertificate, client side: turns the message body back into the Certificate message body it replaces.</summary>
internal static class CertificateCompression
{
    public const ushort Zlib = 1;
    public const ushort Brotli = 2;
    public const ushort Zstd = 3;

    /// <summary>RFC 8879 caps the uncompressed certificate message at 2^24 bytes.</summary>
    private const int MaxUncompressedLength = 1 << 24;

    /// <param name="body">CompressedCertificate body: algorithm (2), uncompressed_length (3), compressed_certificate_message (3 + n).</param>
    /// <param name="offered">Algorithms the client advertised; the server must pick one of them.</param>
    /// <exception cref="TlsFatalAlert">bad_certificate for anything malformed, unoffered, unsupported or mis-sized, as RFC 8879 requires.</exception>
    public static byte[] Decompress(ReadOnlySpan<byte> body, IReadOnlyList<ushort> offered)
    {
        if (body.Length < 8)
        {
            throw BadCertificate();
        }

        var algorithm = BinaryPrimitives.ReadUInt16BigEndian(body);
        var uncompressedLength = ReadUInt24(body[2..]);
        var compressedLength = ReadUInt24(body[5..]);
        var compressed = body[8..];

        if (compressed.Length != compressedLength || compressedLength == 0
            || uncompressedLength == 0 || uncompressedLength > MaxUncompressedLength
            || !offered.Contains(algorithm))
        {
            throw BadCertificate();
        }

        var certificate = new byte[uncompressedLength];
        var ok = algorithm switch
        {
            Brotli => BrotliDecoder.TryDecompress(compressed, certificate, out var written) && written == uncompressedLength,
            Zlib => TryInflate(compressed, certificate),
            _ => false, // zstd: no decoder in the BCL.
        };

        return ok ? certificate : throw BadCertificate();
    }

    private static bool TryInflate(ReadOnlySpan<byte> compressed, byte[] certificate)
    {
        try
        {
            using var zlib = new ZLibStream(new MemoryStream(compressed.ToArray()), CompressionMode.Decompress);
            zlib.ReadExactly(certificate);
            return zlib.ReadByte() == -1;
        }
        catch (Exception exception) when (exception is InvalidDataException or EndOfStreamException)
        {
            return false;
        }
    }

    private static int ReadUInt24(ReadOnlySpan<byte> source) => (source[0] << 16) | (source[1] << 8) | source[2];

    private static TlsFatalAlert BadCertificate() => new(AlertDescription.bad_certificate);
}
