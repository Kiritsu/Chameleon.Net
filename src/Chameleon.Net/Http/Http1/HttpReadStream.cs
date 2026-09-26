using System.Text;

namespace Chameleon.Net.Http.Http1;

/// <summary>Buffered view of a connection: reads response heads and chunk lines, then serves whatever arrived after them
/// (body bytes, the first WebSocket frame) before reading from the inner stream again. Writes pass straight through.</summary>
internal sealed class HttpReadStream(Stream inner) : Stream
{
    private const int MaxHeadSize = 64 * 1024;
    private static readonly byte[] HeadTerminator = "\r\n\r\n"u8.ToArray();
    private static readonly byte[] LineTerminator = "\r\n"u8.ToArray();

    private byte[] _buffer = new byte[4096];
    private int _start;
    private int _end;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    /// <exception cref="HttpIOException">The connection closed early, or the head is malformed or larger than 64 KiB.</exception>
    public async Task<Http1ResponseHead> ReadResponseHeadAsync(CancellationToken cancellationToken)
    {
        var head = await ReadDelimitedAsync(HeadTerminator, MaxHeadSize, cancellationToken).ConfigureAwait(false);
        return Http1ResponseHead.Parse(head.Span);
    }

    /// <summary>Reads one CRLF-terminated line, without the terminator.</summary>
    /// <exception cref="HttpIOException">The connection closed early or the line is longer than <paramref name="maxLength"/>.</exception>
    public async Task<string> ReadLineAsync(int maxLength, CancellationToken cancellationToken)
    {
        var line = await ReadDelimitedAsync(LineTerminator, maxLength, cancellationToken).ConfigureAwait(false);
        return Encoding.Latin1.GetString(line.Span);
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer) => TryReadBuffered(buffer, out var copied) ? copied : inner.Read(buffer);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        TryReadBuffered(buffer.Span, out var copied) ? ValueTask.FromResult(copied) : inner.ReadAsync(buffer, cancellationToken);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => inner.Write(buffer, offset, count);

    public override void Write(ReadOnlySpan<byte> buffer) => inner.Write(buffer);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) =>
        inner.WriteAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        inner.WriteAsync(buffer, offset, count, cancellationToken);

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

    /// <summary>The returned memory aliases the internal buffer and is only valid until the next read.</summary>
    private async Task<ReadOnlyMemory<byte>> ReadDelimitedAsync(byte[] delimiter, int maxLength, CancellationToken cancellationToken)
    {
        var scanned = 0;
        while (true)
        {
            var index = _buffer.AsSpan(_start + scanned, _end - _start - scanned).IndexOf(delimiter);
            if (index >= 0)
            {
                var length = scanned + index;
                var result = _buffer.AsMemory(_start, length);
                _start += length + delimiter.Length;
                return result;
            }

            scanned = Math.Max(0, _end - _start - (delimiter.Length - 1));
            if (_end - _start >= maxLength)
            {
                throw new HttpIOException(HttpRequestError.InvalidResponse, $"Response head or line exceeds {maxLength} bytes.");
            }

            MakeRoom();
            var read = await inner.ReadAsync(_buffer.AsMemory(_end), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new HttpIOException(HttpRequestError.ResponseEnded, "The connection closed before the response was complete.");
            }

            _end += read;
        }
    }

    private bool TryReadBuffered(Span<byte> destination, out int copied)
    {
        copied = Math.Min(destination.Length, _end - _start);
        if (copied == 0)
        {
            return false;
        }

        _buffer.AsSpan(_start, copied).CopyTo(destination);
        _start += copied;
        return true;
    }

    private void MakeRoom()
    {
        if (_start == _end)
        {
            _start = _end = 0;
        }

        if (_end < _buffer.Length)
        {
            return;
        }

        if (_start > 0)
        {
            _buffer.AsSpan(_start, _end - _start).CopyTo(_buffer);
            _end -= _start;
            _start = 0;
            return;
        }

        Array.Resize(ref _buffer, _buffer.Length * 2);
    }
}
