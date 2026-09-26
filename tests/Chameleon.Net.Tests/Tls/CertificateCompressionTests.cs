using System.IO.Compression;
using Chameleon.Net.Tls;
using Org.BouncyCastle.Tls;

namespace Chameleon.Net.Tests.Tls;

public sealed class CertificateCompressionTests
{
    private static readonly byte[] CertificateMessage = [.. Enumerable.Range(0, 3000).Select(static i => (byte)(i % 7))];

    [Theory]
    [InlineData(CertificateCompression.Brotli)]
    [InlineData(CertificateCompression.Zlib)]
    public void RoundTrips(ushort algorithm)
    {
        var body = Body(algorithm, Compress(algorithm, CertificateMessage), CertificateMessage.Length);

        Assert.Equal(CertificateMessage, CertificateCompression.Decompress(body, [CertificateCompression.Brotli, CertificateCompression.Zlib]));
    }

    [Fact]
    public void AlgorithmThatWasNotOfferedIsRejected()
    {
        var body = Body(CertificateCompression.Zlib, Compress(CertificateCompression.Zlib, CertificateMessage), CertificateMessage.Length);

        AssertBadCertificate(() => CertificateCompression.Decompress(body, [CertificateCompression.Brotli]));
    }

    [Fact]
    public void WrongUncompressedLengthIsRejected()
    {
        var body = Body(CertificateCompression.Brotli, Compress(CertificateCompression.Brotli, CertificateMessage), CertificateMessage.Length + 1);

        AssertBadCertificate(() => CertificateCompression.Decompress(body, [CertificateCompression.Brotli]));
    }

    [Fact]
    public void ZstdIsRejectedEvenWhenOffered()
    {
        AssertBadCertificate(() => CertificateCompression.Decompress(Body(CertificateCompression.Zstd, [1, 2, 3], 10), [CertificateCompression.Zstd]));
    }

    [Fact]
    public void TruncatedBodyIsRejected()
    {
        AssertBadCertificate(() => CertificateCompression.Decompress([0, 2, 0, 0], [CertificateCompression.Brotli]));
    }

    private static void AssertBadCertificate(Action action) =>
        Assert.Equal(AlertDescription.bad_certificate, Assert.Throws<TlsFatalAlert>(action).AlertDescription);

    private static byte[] Body(ushort algorithm, byte[] compressed, int uncompressedLength) =>
    [
        (byte)(algorithm >> 8), (byte)algorithm,
        (byte)(uncompressedLength >> 16), (byte)(uncompressedLength >> 8), (byte)uncompressedLength,
        (byte)(compressed.Length >> 16), (byte)(compressed.Length >> 8), (byte)compressed.Length,
        .. compressed,
    ];

    private static byte[] Compress(ushort algorithm, byte[] data)
    {
        using var output = new MemoryStream();
        using (Stream compressor = algorithm == CertificateCompression.Brotli
                   ? new BrotliStream(output, CompressionLevel.Optimal, leaveOpen: true)
                   : new ZLibStream(output, CompressionLevel.Optimal, leaveOpen: true))
        {
            compressor.Write(data);
        }

        return output.ToArray();
    }
}
