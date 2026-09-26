using System.Buffers.Binary;

namespace Chameleon.Net.Http.Http2;

internal sealed class Http2FrameReader(Stream stream)
{
    private byte[] _buffer = new byte[Http2Frame.HeaderLength + Http2Frame.DefaultMaxFrameSize];
    private int _start;
    private int _end;

    /// <returns>Null on a clean end of stream at a frame boundary. The payload aliases the internal buffer until the next call.</returns>
    /// <exception cref="Http2ConnectionException">The frame is larger than <paramref name="maxFrameSize"/>.</exception>
    public async ValueTask<(Http2FrameHeader Header, ReadOnlyMemory<byte> Payload)?> ReadAsync(int maxFrameSize, CancellationToken cancellationToken)
    {
        if (!await FillAsync(Http2Frame.HeaderLength, allowEndOfStream: true, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var raw = _buffer.AsSpan(_start, Http2Frame.HeaderLength);
        var header = new Http2FrameHeader(
            (raw[0] << 16) | (raw[1] << 8) | raw[2],
            (Http2FrameType)raw[3],
            raw[4],
            BinaryPrimitives.ReadInt32BigEndian(raw[5..]) & int.MaxValue);

        if (header.Length > maxFrameSize)
        {
            throw new Http2ConnectionException(Http2ErrorCode.FrameSizeError, $"Received a {header.Length}-byte frame; the limit is {maxFrameSize}.");
        }

        await FillAsync(Http2Frame.HeaderLength + header.Length, allowEndOfStream: false, cancellationToken).ConfigureAwait(false);
        var payload = _buffer.AsMemory(_start + Http2Frame.HeaderLength, header.Length);
        _start += Http2Frame.HeaderLength + header.Length;
        return (header, payload);
    }

    private async ValueTask<bool> FillAsync(int count, bool allowEndOfStream, CancellationToken cancellationToken)
    {
        if (_end - _start >= count)
        {
            return true;
        }

        if (_buffer.Length - _start < count)
        {
            var target = _buffer.Length < count ? new byte[Math.Max(count, _buffer.Length * 2)] : _buffer;
            _buffer.AsSpan(_start, _end - _start).CopyTo(target);
            _end -= _start;
            _start = 0;
            _buffer = target;
        }

        while (_end - _start < count)
        {
            var read = await stream.ReadAsync(_buffer.AsMemory(_end), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return allowEndOfStream && _end == _start
                    ? false
                    : throw new IOException("The connection closed in the middle of an HTTP/2 frame.");
            }

            _end += read;
        }

        return true;
    }
}
