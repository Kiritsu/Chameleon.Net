using System.Globalization;
using System.Text;

namespace Chameleon.Net.Http.Http1;

/// <summary>Read-only response body. Tells the connection exactly once whether it can be reused: at the end of the body, or when disposed early.</summary>
internal abstract class Http1BodyStream(Http1Connection connection, HttpReadStream source) : Stream
{
    private bool _completed;

    protected HttpReadStream Source => source;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public sealed override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_completed || buffer.IsEmpty)
        {
            return 0;
        }

        // Blocking TLS reads ignore the token; closing the connection is what unblocks them.
        await using (cancellationToken.Register(static state => ((Http1Connection)state!).Abort(), connection).ConfigureAwait(false))
        {
            try
            {
                return await ReadBodyAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception)
            {
                Complete(reusable: false);
                if (cancellationToken.IsCancellationRequested && exception is not OperationCanceledException)
                {
                    throw new OperationCanceledException("Reading the response body was canceled.", exception, cancellationToken);
                }

                throw;
            }
        }
    }

    public sealed override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public sealed override int Read(byte[] buffer, int offset, int count) =>
        ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected abstract ValueTask<int> ReadBodyAsync(Memory<byte> buffer, CancellationToken cancellationToken);

    protected void Complete(bool reusable)
    {
        if (_completed)
        {
            return;
        }

        _completed = true;
        connection.BodyFinished(reusable);
    }

    protected static HttpIOException Truncated() =>
        new(HttpRequestError.ResponseEnded, "The connection closed before the response body was complete.");

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            Complete(reusable: false);
        }

        base.Dispose(disposing);
    }
}

internal sealed class ContentLengthBodyStream(Http1Connection connection, HttpReadStream source, long length)
    : Http1BodyStream(connection, source)
{
    private long _remaining = length;

    protected override async ValueTask<int> ReadBodyAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var read = await Source.ReadAsync(buffer[..(int)Math.Min(buffer.Length, _remaining)], cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            throw Truncated();
        }

        _remaining -= read;
        if (_remaining == 0)
        {
            Complete(reusable: true);
        }

        return read;
    }
}

internal sealed class ChunkedBodyStream(Http1Connection connection, HttpReadStream source) : Http1BodyStream(connection, source)
{
    private const int MaxLineLength = 16 * 1024;
    private long _remainingInChunk;

    protected override async ValueTask<int> ReadBodyAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (_remainingInChunk == 0)
        {
            var sizeLine = await Source.ReadLineAsync(MaxLineLength, cancellationToken).ConfigureAwait(false);
            var size = sizeLine.AsSpan();
            var extension = size.IndexOf(';');
            if (extension >= 0)
            {
                size = size[..extension];
            }

            if (!long.TryParse(size.Trim(' '), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out _remainingInChunk) || _remainingInChunk < 0)
            {
                throw new HttpIOException(HttpRequestError.InvalidResponse, $"Invalid chunk size line '{sizeLine}'.");
            }

            if (_remainingInChunk == 0)
            {
                // Trailer fields are read and dropped.
                while ((await Source.ReadLineAsync(MaxLineLength, cancellationToken).ConfigureAwait(false)).Length > 0)
                {
                }

                Complete(reusable: true);
                return 0;
            }
        }

        var read = await Source.ReadAsync(buffer[..(int)Math.Min(buffer.Length, _remainingInChunk)], cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            throw Truncated();
        }

        _remainingInChunk -= read;
        if (_remainingInChunk == 0 && (await Source.ReadLineAsync(MaxLineLength, cancellationToken).ConfigureAwait(false)).Length != 0)
        {
            throw new HttpIOException(HttpRequestError.InvalidResponse, "Chunk data is not followed by CRLF.");
        }

        return read;
    }
}

/// <summary>No Content-Length and not chunked: the body ends when the server closes, so the connection is never reused.</summary>
internal sealed class CloseDelimitedBodyStream(Http1Connection connection, HttpReadStream source) : Http1BodyStream(connection, source)
{
    protected override async ValueTask<int> ReadBodyAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var read = await Source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            Complete(reusable: false);
        }

        return read;
    }
}

/// <summary>Write-only request body framing on top of a connection.</summary>
internal abstract class Http1RequestBodyStream(Stream destination) : Stream
{
    protected Stream Destination => destination;

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public sealed override void Write(byte[] buffer, int offset, int count) =>
        WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public sealed override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public abstract override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default);

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();
}

internal sealed class ChunkedRequestBodyStream(Stream destination) : Http1RequestBodyStream(destination)
{
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
        {
            return;
        }

        // One write per chunk, so each chunk goes out as a single TLS record.
        var header = Encoding.ASCII.GetBytes(buffer.Length.ToString("x", CultureInfo.InvariantCulture) + "\r\n");
        var chunk = new byte[header.Length + buffer.Length + 2];
        header.CopyTo(chunk, 0);
        buffer.Span.CopyTo(chunk.AsSpan(header.Length));
        "\r\n"u8.CopyTo(chunk.AsSpan(header.Length + buffer.Length));
        await Destination.WriteAsync(chunk, cancellationToken).ConfigureAwait(false);
    }

    public Task CompleteAsync(CancellationToken cancellationToken) => Destination.WriteAsync("0\r\n\r\n"u8.ToArray(), cancellationToken).AsTask();
}

/// <summary>Guards the promise made by Content-Length: writing more or less would desynchronise the connection.</summary>
internal sealed class ContentLengthRequestBodyStream(Stream destination, long length) : Http1RequestBodyStream(destination)
{
    private long _remaining = length;

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.Length > _remaining)
        {
            throw new HttpRequestException(HttpRequestError.Unknown, "The request content is longer than its Content-Length.");
        }

        _remaining -= buffer.Length;
        await Destination.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public void EnsureComplete()
    {
        if (_remaining != 0)
        {
            throw new HttpRequestException(HttpRequestError.Unknown, "The request content is shorter than its Content-Length.");
        }
    }
}
