namespace Chameleon.Net.Http.Http2;

internal sealed class Http2ResponseBodyStream(Http2Stream stream) : Stream
{
    private bool _finished;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_finished || buffer.IsEmpty)
        {
            return 0;
        }

        try
        {
            var read = await stream.Connection.ReadBodyAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
            _finished = read == 0;
            return read;
        }
        catch
        {
            _finished = true;
            stream.Connection.Reset(stream, Http2ErrorCode.Cancel);
            throw;
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_finished)
        {
            _finished = true;
            stream.Connection.Reset(stream, Http2ErrorCode.Cancel);
        }

        base.Dispose(disposing);
    }
}

/// <summary>Buffers like OkHttp's FramingSink: full 16 KiB DATA frames while writing, the remainder with END_STREAM on completion
/// (an empty DATA frame with END_STREAM when nothing is left).</summary>
internal sealed class Http2RequestBodyStream(Http2Connection connection, Http2Stream stream) : Stream
{
    private const int EmitSize = 16 * 1024;

    private readonly byte[] _buffer = new byte[EmitSize];
    private int _count;

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        while (!buffer.IsEmpty)
        {
            var count = Math.Min(EmitSize - _count, buffer.Length);
            buffer.Span[..count].CopyTo(_buffer.AsSpan(_count));
            _count += count;
            buffer = buffer[count..];

            if (_count == EmitSize)
            {
                await connection.SendDataAsync(stream, _buffer, endStream: false, cancellationToken).ConfigureAwait(false);
                _count = 0;
            }
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public Task CompleteAsync(CancellationToken cancellationToken) =>
        connection.SendDataAsync(stream, _buffer.AsMemory(0, _count), endStream: true, cancellationToken);

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}
