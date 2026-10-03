namespace Chameleon.Net.Inspector.Server;

/// <summary>Returns bytes already read off the socket (the ClientHello, a sniffed prefix) before reading the socket again.</summary>
internal sealed class ReplayStream(ReadOnlyMemory<byte> prefix, Stream inner) : Stream
{
    private ReadOnlyMemory<byte> _prefix = prefix;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (_prefix.IsEmpty)
        {
            return inner.Read(buffer);
        }

        var count = Math.Min(buffer.Length, _prefix.Length);
        _prefix.Span[..count].CopyTo(buffer);
        _prefix = _prefix[count..];
        return count;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_prefix.IsEmpty)
        {
            return inner.ReadAsync(buffer, cancellationToken);
        }

        var count = Math.Min(buffer.Length, _prefix.Length);
        _prefix.Span[..count].CopyTo(buffer.Span);
        _prefix = _prefix[count..];
        return ValueTask.FromResult(count);
    }

    public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        inner.WriteAsync(buffer, offset, count, cancellationToken);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        inner.WriteAsync(buffer, cancellationToken);

    public override void Flush() => inner.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            inner.Dispose();
        }

        base.Dispose(disposing);
    }
}
