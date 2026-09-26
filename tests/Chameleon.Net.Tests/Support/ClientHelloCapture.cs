using System.Net;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Org.BouncyCastle.Security;

namespace Chameleon.Net.Tests.Support;

/// <summary>Runs the real handshake pipeline against a transport that records writes and refuses reads, so the emitted ClientHello can be inspected offline.</summary>
internal static class ClientHelloCapture
{
    public static async Task<byte[]> CaptureAsync(TlsProfile profile, string host, SecureRandom? random = null)
    {
        random ??= new SecureRandom();
        var transport = new CapturingTransport();
        var factory = new BouncyCastleTlsConnectionFactory(
            new ProfileTlsClientFactory(), new ClientHelloEncoder(random), new SystemCertificateValidator(), random);

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await factory.ConnectAsync(transport, host, 443, profile, TestContext.Current.CancellationToken));

        Assert.NotEmpty(transport.Written);
        return transport.Written;
    }

    private sealed class CapturingTransport : ITransport
    {
        private readonly List<byte> _written = [];

        public byte[] Written => [.. _written];

        public Task<Stream> ConnectAsync(DnsEndPoint endpoint, CancellationToken cancellationToken = default) =>
            Task.FromResult<Stream>(new CaptureStream(_written));
    }

    private sealed class CaptureStream(List<byte> written) : Stream
    {

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count) => written.AddRange(buffer.AsSpan(offset, count));

        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("Capture transport: no server.");

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
