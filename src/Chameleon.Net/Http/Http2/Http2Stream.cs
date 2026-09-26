namespace Chameleon.Net.Http.Http2;

/// <summary>One request/response exchange. Receive-side state is fed by the connection's read loop and drained by the response body.</summary>
internal sealed class Http2Stream(Http2Connection connection, HttpRequestMessage request)
{
    private readonly Lock _sync = new();
    private readonly Queue<byte[]> _data = new();
    private readonly TaskCompletionSource<List<KeyValuePair<string, string>>> _responseHeaders = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _headOffset;
    private bool _remoteEnded;
    private bool _discarding;
    private Exception? _error;
    private TaskCompletionSource? _waiter;
    private List<KeyValuePair<string, string>>? _trailers;

    /// <summary>Consumed bytes not yet returned to the server with a stream-level WINDOW_UPDATE.</summary>
    public int Unacknowledged;

    public Http2Connection Connection => connection;

    public HttpRequestMessage Request => request;

    /// <summary>0 until the HEADERS frame is written.</summary>
    public int Id { get; set; }

    /// <summary>Guarded by the connection's flow-control lock.</summary>
    public long SendWindow { get; set; }

    public HttpResponseMessage? Response { get; set; }

    public Task<List<KeyValuePair<string, string>>> ResponseHeaders => _responseHeaders.Task;

    public Exception? Error
    {
        get
        {
            lock (_sync)
            {
                return _error;
            }
        }
    }

    public bool RemoteEnded
    {
        get
        {
            lock (_sync)
            {
                return _remoteEnded;
            }
        }
    }

    /// <exception cref="HttpIOException">The header block has no valid <c>:status</c>.</exception>
    public void OnHeaders(List<KeyValuePair<string, string>> headers)
    {
        if (_responseHeaders.Task.IsCompleted)
        {
            lock (_sync)
            {
                _trailers = headers;
            }

            return;
        }

        var status = headers.Find(static header => header.Key == ":status").Value;
        if (status is not { Length: 3 } || !status.All(char.IsAsciiDigit))
        {
            throw new HttpIOException(HttpRequestError.InvalidResponse, $"Invalid :status '{status}'.");
        }

        // Interim responses (100 Continue, 103 Early Hints) are skipped; the final one follows.
        if (status[0] != '1' || status == "101")
        {
            _responseHeaders.TrySetResult(headers);
        }
    }

    /// <returns>False when the data was dropped because nobody will read it; the caller credits the connection window.</returns>
    public bool OnData(ReadOnlySpan<byte> payload)
    {
        lock (_sync)
        {
            if (_discarding || _error is not null)
            {
                return false;
            }

            if (!payload.IsEmpty)
            {
                _data.Enqueue(payload.ToArray());
                Signal();
            }

            return true;
        }
    }

    public void OnRemoteEnd()
    {
        lock (_sync)
        {
            _remoteEnded = true;
            Signal();
        }

        _responseHeaders.TrySetException(new HttpIOException(HttpRequestError.InvalidResponse, "The stream ended without a final response."));
    }

    public void Fail(Exception error)
    {
        _responseHeaders.TrySetException(error);
        lock (_sync)
        {
            _error ??= error;
            Signal();
        }
    }

    /// <returns>Bytes that were buffered and are now dropped, to be credited back to the connection window.</returns>
    public int Discard()
    {
        lock (_sync)
        {
            _discarding = true;
            var dropped = _data.Sum(static chunk => chunk.Length) - _headOffset;
            _data.Clear();
            _headOffset = 0;
            return dropped;
        }
    }

    public async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task wait;
            lock (_sync)
            {
                if (_data.TryPeek(out var chunk))
                {
                    var count = Math.Min(buffer.Length, chunk.Length - _headOffset);
                    chunk.AsSpan(_headOffset, count).CopyTo(buffer.Span);
                    _headOffset += count;
                    if (_headOffset == chunk.Length)
                    {
                        _data.Dequeue();
                        _headOffset = 0;
                    }

                    return count;
                }

                if (_error is not null)
                {
                    throw new HttpIOException(HttpRequestError.HttpProtocolError, "The HTTP/2 stream failed before the response body was complete.", _error);
                }

                if (_remoteEnded)
                {
                    ApplyTrailers();
                    return 0;
                }

                _waiter = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                wait = _waiter.Task;
            }

            await wait.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private void ApplyTrailers()
    {
        if (_trailers is null || Response is null)
        {
            return;
        }

        foreach (var (name, value) in _trailers)
        {
            Response.TrailingHeaders.TryAddWithoutValidation(name, value);
        }

        _trailers = null;
    }

    private void Signal()
    {
        _waiter?.TrySetResult();
        _waiter = null;
    }
}
