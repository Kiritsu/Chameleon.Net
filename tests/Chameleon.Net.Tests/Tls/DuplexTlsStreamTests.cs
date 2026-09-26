using Chameleon.Net.Tls;

namespace Chameleon.Net.Tests.Tls;

public sealed class DuplexTlsStreamTests
{
    [Fact]
    public async Task PendingReadDoesNotBlockWrites()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var blocking = new BlockingStream();
        await using var duplex = new DuplexTlsStream(blocking, Stream.Null);

        var pendingRead = duplex.ReadAsync(new byte[1], cancellationToken).AsTask();
        await blocking.ReadStarted.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);

        await duplex.WriteAsync(new byte[] { 42 }, cancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);

        Assert.False(pendingRead.IsCompleted);
        Assert.Equal([42], blocking.Written);
        blocking.ReleaseRead();
        Assert.Equal(1, await pendingRead.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken));
    }

    /// <summary>Synchronous-only stream whose reads block until released, like BouncyCastle's TLS stream waiting for a record.</summary>
    private sealed class BlockingStream : Stream
    {
        private readonly SemaphoreSlim _readGate = new(0);
        private readonly TaskCompletionSource _readStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly List<byte> _written = [];

        public Task ReadStarted => _readStarted.Task;
        public byte[] Written => [.. _written];

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public void ReleaseRead() => _readGate.Release();

        public override int Read(byte[] buffer, int offset, int count)
        {
            _readStarted.TrySetResult();
            _readGate.Wait();
            buffer[offset] = 1;
            return 1;
        }

        public override void Write(byte[] buffer, int offset, int count) => _written.AddRange(buffer.AsSpan(offset, count));

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _readGate.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
