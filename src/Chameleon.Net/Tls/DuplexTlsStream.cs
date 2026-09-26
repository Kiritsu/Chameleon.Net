namespace Chameleon.Net.Tls;

/// <summary>BouncyCastle's TLS stream is blocking, and <see cref="Stream"/>'s default async methods serialize reads and writes on a single semaphore,
/// so a pending read would block every write — fatal for WebSockets and HTTP/2. Reads and writes are offloaded independently instead;
/// BouncyCastle supports one concurrent reader and one concurrent writer.</summary>
internal sealed class DuplexTlsStream(Stream tls, Stream transport) : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => tls.Read(buffer, offset, count);

    public override int Read(Span<byte> buffer) => tls.Read(buffer);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        new(Task.Run(() => tls.Read(buffer.Span), cancellationToken));

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => tls.Write(buffer, offset, count);

    public override void Write(ReadOnlySpan<byte> buffer) => tls.Write(buffer);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        new(Task.Run(() => tls.Write(buffer.Span), cancellationToken));

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Flush() => tls.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.Run(tls.Flush, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            try
            {
                tls.Dispose();
            }
            finally
            {
                transport.Dispose();
            }
        }

        base.Dispose(disposing);
    }
}
