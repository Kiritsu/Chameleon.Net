using System.Buffers;
using System.Runtime.InteropServices;
using Org.BouncyCastle.Tls;

namespace Chameleon.Net.Tls;

/// <summary>TLS over an async transport, with BouncyCastle in non-blocking mode: bytes read from the socket are offered to the protocol, and
/// the records it produces are written back, all with async I/O. An idle connection waiting for data holds no thread, unlike
/// BouncyCastle's blocking stream, which needs one per pending read (one per WebSocket, one per HTTP/2 connection).</summary>
/// <remarks>BouncyCastle's protocol object isn't thread-safe, so every call into it happens under one lock; socket I/O happens outside it.
/// One receive and one send can be in flight at the same time. Records leave in the order the protocol produced them: whoever sends
/// takes everything queued so far, under the send lock.</remarks>
internal sealed class NonBlockingTlsStream : Stream
{
    /// <summary>A full TLS record (16 KiB of plaintext plus header and expansion).</summary>
    private const int ReceiveBufferSize = (16 * 1024) + 2048;

    private readonly TlsClientProtocol _protocol;
    private readonly Stream _transport;
    private readonly Lock _protocolLock = new();
    private readonly SemaphoreSlim _receiveLock = new(1, 1);
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly byte[] _receiveBuffer = new byte[ReceiveBufferSize];
    private int _disposed;

    public NonBlockingTlsStream(TlsClientProtocol protocol, Stream transport)
    {
        _protocol = protocol;
        _transport = transport;
    }

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    /// <summary>Runs the handshake: sends the ClientHello, then feeds the server's flights to the protocol until it is done.</summary>
    public async Task HandshakeAsync(TlsClient client, CancellationToken cancellationToken)
    {
        lock (_protocolLock)
        {
            _protocol.Connect(client);
        }

        await SendPendingAsync(cancellationToken).ConfigureAwait(false);
        while (IsHandshaking())
        {
            await ReceiveAsync(cancellationToken).ConfigureAwait(false);
        }

        lock (_protocolLock)
        {
            if (!_protocol.IsConnected)
            {
                throw new TlsFatalAlert(AlertDescription.internal_error, "The TLS connection closed during the handshake.");
            }
        }
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
        {
            return 0;
        }

        await _receiveLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            while (true)
            {
                lock (_protocolLock)
                {
                    var available = _protocol.GetAvailableInputBytes();
                    if (available > 0)
                    {
                        return ReadInput(buffer, Math.Min(available, buffer.Length));
                    }

                    if (_protocol.IsClosed)
                    {
                        return 0;
                    }
                }

                await ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _receiveLock.Release();
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
        {
            return;
        }

        lock (_protocolLock)
        {
            _protocol.WriteApplicationData(buffer.Span);
        }

        await SendPendingAsync(cancellationToken).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

    public override Task FlushAsync(CancellationToken cancellationToken) => SendPendingAsync(cancellationToken);

    public override void Flush() => SendPendingAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            try
            {
                SendCloseNotify();
            }
            finally
            {
                _transport.Dispose();
                _receiveLock.Dispose();
                _sendLock.Dispose();
            }
        }

        base.Dispose(disposing);
    }

    private bool IsHandshaking()
    {
        lock (_protocolLock)
        {
            return _protocol.IsHandshaking;
        }
    }

    /// <summary>Reads what the socket has and hands it to the protocol (end of stream included), then sends whatever that produced.</summary>
    private async Task ReceiveAsync(CancellationToken cancellationToken)
    {
        var read = await _transport.ReadAsync(_receiveBuffer, cancellationToken).ConfigureAwait(false);
        try
        {
            lock (_protocolLock)
            {
                if (read == 0)
                {
                    // Throws TlsNoCloseNotifyException if the peer hung up without close_notify, as the blocking stream did.
                    _protocol.CloseInput();
                }
                else
                {
                    _protocol.OfferInput(_receiveBuffer, 0, read);
                }
            }
        }
        catch (IOException)
        {
            // The protocol queued an alert explaining the failure; try to get it out before reporting.
            await TrySendPendingAsync().ConfigureAwait(false);
            throw;
        }

        await SendPendingAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task SendPendingAsync(CancellationToken cancellationToken)
    {
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            byte[] pending;
            int length;
            lock (_protocolLock)
            {
                length = _protocol.GetAvailableOutputBytes();
                if (length == 0)
                {
                    return;
                }

                pending = ArrayPool<byte>.Shared.Rent(length);
                _protocol.ReadOutput(pending, 0, length);
            }

            try
            {
                await _transport.WriteAsync(pending.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                await _transport.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(pending);
            }
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private async Task TrySendPendingAsync()
    {
        try
        {
            await SendPendingAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException)
        {
            // Best effort: the connection is failing anyway.
        }
    }

    /// <summary>Best effort and without waiting for a send in progress: closing must not block on a stalled peer.</summary>
    private void SendCloseNotify()
    {
        try
        {
            byte[] closing;
            lock (_protocolLock)
            {
                if (!_protocol.IsClosed)
                {
                    _protocol.Close();
                }

                closing = new byte[_protocol.GetAvailableOutputBytes()];
                _protocol.ReadOutput(closing, 0, closing.Length);
            }

            if (closing.Length > 0 && _sendLock.Wait(0))
            {
                try
                {
                    _transport.Write(closing);
                }
                finally
                {
                    _sendLock.Release();
                }
            }
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException)
        {
            // Already broken.
        }
    }

    private int ReadInput(Memory<byte> buffer, int count)
    {
        if (MemoryMarshal.TryGetArray<byte>(buffer, out var segment))
        {
            return _protocol.ReadInput(segment.Array!, segment.Offset, count);
        }

        var rented = ArrayPool<byte>.Shared.Rent(count);
        try
        {
            var read = _protocol.ReadInput(rented, 0, count);
            rented.AsSpan(0, read).CopyTo(buffer.Span);
            return read;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}
