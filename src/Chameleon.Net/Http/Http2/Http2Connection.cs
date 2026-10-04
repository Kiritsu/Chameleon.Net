using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using Chameleon.Net.Http.Http2.Hpack;
using Chameleon.Net.Profiles;
using Microsoft.Extensions.Logging;

namespace Chameleon.Net.Http.Http2;

/// <summary>HTTP/2 client connection whose observable behaviour — connection preface, SETTINGS order, WINDOW_UPDATE, PRIORITY frames,
/// pseudo-header order, HEADERS priority, HPACK representation, window updates — follows the profile.</summary>
internal sealed class Http2Connection : IHttpConnection
{
    private static readonly FrozenSet<string> ConnectionSpecific = FrozenSet.Create(StringComparer.OrdinalIgnoreCase,
        "Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade", "Host", "TE");

    private static readonly PseudoHeader[] AllPseudoHeaders = [PseudoHeader.Method, PseudoHeader.Authority, PseudoHeader.Scheme, PseudoHeader.Path];

    private readonly Stream _stream;
    private readonly Http2FrameReader _reader;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly HpackEncoder _encoder;
    private readonly HpackDecoder _decoder;
    private readonly ConcurrentDictionary<int, Http2Stream> _streams = new();
    private readonly Lock _flowLock = new();
    private readonly Lock _slotLock = new();
    private readonly Queue<TaskCompletionSource> _slotWaiters = new();
    private readonly int _localMaxFrameSize;
    private readonly int _windowUpdateThreshold;
    private readonly ILogger _logger;

    private TaskCompletionSource _flowChanged = NewSignal();
    private long _connectionSendWindow = Http2Frame.DefaultWindowSize;
    private int _peerInitialWindow = Http2Frame.DefaultWindowSize;
    private int _peerMaxFrameSize = Http2Frame.DefaultMaxFrameSize;
    private int _peerMaxConcurrentStreams = int.MaxValue;
    private int _activeStreams;
    private int _nextStreamId;
    private int _connectionUnacknowledged;
    private volatile bool _goingAway;
    private volatile bool _retired;
    private long _idleSince = Stopwatch.GetTimestamp();
    private int _closed;

    private List<byte>? _headerBlock;
    private int _headerBlockStreamId;
    private bool _headerBlockEndStream;
    private int _pushPromisedStreamId;

    private Http2Connection(Origin origin, ClientProfile profile, Stream stream, ILogger logger)
    {
        Origin = origin;
        Profile = profile;
        _stream = stream;
        _logger = logger;
        _reader = new Http2FrameReader(stream);

        var settings = profile.Http2.Preface.OfType<Http2SettingsFrame>().FirstOrDefault()?.Settings ?? [];
        var localInitialWindow = (int)Math.Min(LocalSetting(settings, Http2SettingId.InitialWindowSize, Http2Frame.DefaultWindowSize), int.MaxValue);
        _localMaxFrameSize = (int)Math.Clamp(LocalSetting(settings, Http2SettingId.MaxFrameSize, Http2Frame.DefaultMaxFrameSize),
            Http2Frame.DefaultMaxFrameSize, Http2Frame.MaxAllowedFrameSize);
        _decoder = new HpackDecoder((int)Math.Min(LocalSetting(settings, Http2SettingId.HeaderTableSize, Http2Frame.DefaultHeaderTableSize), int.MaxValue));
        _encoder = new HpackEncoder(profile.Http2.Hpack?.Indexing ?? HpackIndexing.OkHttp);

        // OkHttp acknowledges consumed bytes once half the initial window is used, per stream and per connection.
        _windowUpdateThreshold = Math.Max(1, localInitialWindow / 2);

        // Streams named by preface PRIORITY frames (Firefox uses 3..13 as grouping nodes) are not available for requests.
        var highestPriorityStream = profile.Http2.Preface.OfType<Http2PriorityFrame>().Select(static frame => (int)frame.StreamId).DefaultIfEmpty(-1).Max();
        var afterPriorityFrames = highestPriorityStream < 1 ? 1 : highestPriorityStream + (highestPriorityStream % 2 == 1 ? 2 : 1);
        _nextStreamId = Math.Max(afterPriorityFrames, (int)(profile.Http2.FirstStreamId | 1));
    }

    public Origin Origin { get; }

    public ClientProfile Profile { get; }

    public bool IsReusable => !_goingAway && !_retired && Volatile.Read(ref _closed) == 0 && _nextStreamId < int.MaxValue - 2;

    public bool IsClosed => Volatile.Read(ref _closed) != 0;

    /// <summary>How long the connection has had no open stream, or null while it is in use.</summary>
    public TimeSpan? IdleTime
    {
        get
        {
            lock (_slotLock)
            {
                return _activeStreams == 0 && _slotWaiters.Count == 0 ? Stopwatch.GetElapsedTime(_idleSince) : null;
            }
        }
    }

    /// <summary>Atomically stops accepting streams if the connection has been idle for at least <paramref name="minimumIdle"/>;
    /// a request racing for it gets a replayable failure instead of a connection that is about to close.</summary>
    public bool TryRetire(TimeSpan minimumIdle)
    {
        lock (_slotLock)
        {
            if (_activeStreams != 0 || _slotWaiters.Count != 0 || Stopwatch.GetElapsedTime(_idleSince) < minimumIdle)
            {
                return false;
            }

            _retired = true;
            return true;
        }
    }

    public static async Task<Http2Connection> OpenAsync(Origin origin, ClientProfile profile, Stream stream, ILogger logger, CancellationToken cancellationToken)
    {
        var connection = new Http2Connection(origin, profile, stream, logger);
        await stream.WriteAsync(Preface(profile.Http2), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        _ = Task.Run(connection.ReadLoopAsync, CancellationToken.None);
        return connection;
    }

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, RequestKind kind, string? cookieHeader, CancellationToken cancellationToken)
    {
        var plan = RequestHeaderBuilder.Build(request, Profile, kind, cookieHeader, http2: true);
        var headers = RequestHeaders(request, plan);
        HeaderValidation.Validate(headers.Where(static header => !header.Key.StartsWith(':')));

        await AcquireStreamSlotAsync(cancellationToken).ConfigureAwait(false);
        var stream = new Http2Stream(this, request);
        var endStream = request.Content is null;
        try
        {
            await using (cancellationToken.Register(static state => Cancel((Http2Stream)state!), stream).ConfigureAwait(false))
            {
                await WriteHeadersAsync(stream, headers, endStream, Profile.Http2.PriorityFor(kind), cancellationToken).ConfigureAwait(false);
                if (!endStream)
                {
                    var body = new Http2RequestBodyStream(this, stream);
                    await request.Content!.CopyToAsync(body, cancellationToken).ConfigureAwait(false);
                    await body.CompleteAsync(cancellationToken).ConfigureAwait(false);
                }

                var responseHeaders = await stream.ResponseHeaders.WaitAsync(cancellationToken).ConfigureAwait(false);
                return CreateResponse(request, stream, responseHeaders, plan.TransparentDecompression);
            }
        }
        catch (Exception exception) when (cancellationToken.IsCancellationRequested)
        {
            Reset(stream, Http2ErrorCode.Cancel);
            ReleaseIfNeverOpened(stream);
            if (exception is OperationCanceledException)
            {
                throw;
            }

            throw new OperationCanceledException("The request was canceled.", exception, cancellationToken);
        }
        catch (Http2RetryableException exception) when (HttpContentReplay.IsReplayable(request.Content))
        {
            ReleaseIfNeverOpened(stream);
            throw new StaleConnectionException(exception);
        }
        catch (IOException exception)
        {
            Reset(stream, Http2ErrorCode.Cancel);
            ReleaseIfNeverOpened(stream);
            throw new HttpRequestException(
                exception is HttpIOException http ? http.HttpRequestError : HttpRequestError.HttpProtocolError,
                $"The HTTP/2 exchange with {Origin.Host} failed.",
                exception);
        }
        catch
        {
            Reset(stream, Http2ErrorCode.Cancel);
            ReleaseIfNeverOpened(stream);
            throw;
        }
    }

    /// <summary>Closes the socket without GOAWAY, as OkHttp's pool does when it evicts a connection.</summary>
    public void Dispose() => Close(new ObjectDisposedException(nameof(Http2Connection)));

    internal async ValueTask<int> ReadBodyAsync(Http2Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (read > 0)
        {
            CreditConnection(read);
            if (!stream.RemoteEnded && Interlocked.Add(ref stream.Unacknowledged, read) >= _windowUpdateThreshold)
            {
                var increment = Interlocked.Exchange(ref stream.Unacknowledged, 0);
                if (increment > 0)
                {
                    SendControl(Http2Frame.WindowUpdate(stream.Id, increment));
                }
            }
        }

        return read;
    }

    /// <summary>Abandons the stream: drops buffered data, fails pending reads, and sends RST_STREAM unless the server already ended it.</summary>
    internal void Reset(Http2Stream stream, Http2ErrorCode code)
    {
        CreditConnection(stream.Discard());
        stream.Fail(new HttpIOException(HttpRequestError.Unknown, $"The HTTP/2 stream was reset ({code})."));
        if (RemoveStream(stream) && !stream.RemoteEnded)
        {
            SendControl(Http2Frame.RstStream(stream.Id, code));
        }
    }

    internal async Task SendDataAsync(Http2Stream stream, ReadOnlyMemory<byte> data, bool endStream, CancellationToken cancellationToken)
    {
        if (data.IsEmpty && !endStream)
        {
            return;
        }

        do
        {
            var count = data.IsEmpty ? 0 : await ReserveWindowAsync(stream, Math.Min(data.Length, Volatile.Read(ref _peerMaxFrameSize)), cancellationToken).ConfigureAwait(false);
            var last = count == data.Length;
            await WriteFrameAsync(Http2Frame.Create(Http2FrameType.Data, last && endStream ? Http2Flags.EndStream : (byte)0, stream.Id, data.Span[..count])).ConfigureAwait(false);
            data = data[count..];
        }
        while (!data.IsEmpty);
    }

    private static void Cancel(Http2Stream stream) => stream.Connection.Reset(stream, Http2ErrorCode.Cancel);

    private List<KeyValuePair<string, string>> RequestHeaders(HttpRequestMessage request, RequestHeaderPlan plan)
    {
        var uri = request.RequestUri!;
        var headers = new List<KeyValuePair<string, string>>();
        foreach (var pseudo in Profile.Http2.PseudoHeaderOrder.Concat(AllPseudoHeaders).Distinct())
        {
            headers.Add(pseudo switch
            {
                PseudoHeader.Method => new(":method", request.Method.Method),
                PseudoHeader.Authority => new(":authority", RequestHeaderBuilder.Authority(request)),
                PseudoHeader.Scheme => new(":scheme", uri.Scheme),
                PseudoHeader.Path => new(":path", uri.PathAndQuery),
                _ => throw new InvalidOperationException($"Unknown pseudo-header {pseudo}."),
            });
        }

        var splitCookies = Profile.Http2.Hpack?.SplitCookies == true;
        foreach (var (name, value) in plan.Headers)
        {
            var isTeTrailers = string.Equals(name, "TE", StringComparison.OrdinalIgnoreCase) && value == "trailers";
            if (splitCookies && string.Equals(name, "Cookie", StringComparison.OrdinalIgnoreCase))
            {
                headers.AddRange(CookieCrumbs(value).Select(static crumb => new KeyValuePair<string, string>("cookie", crumb)));
            }
            else if (!ConnectionSpecific.Contains(name) || isTeTrailers)
            {
                headers.Add(new(name.ToLowerInvariant(), value));
            }
        }

        return headers;
    }

    /// <summary>Chrome's crumbs (quiche <c>CookieToCrumbs</c>): the value trimmed of spaces and tabs, split on ';', each split dropping one
    /// following space.</summary>
    private static IEnumerable<string> CookieCrumbs(string cookie) => cookie
        .Trim(' ', '\t')
        .Split(';')
        .Select(static (crumb, index) => index > 0 && crumb.StartsWith(' ') ? crumb[1..] : crumb);

    private static HttpResponseMessage CreateResponse(HttpRequestMessage request, Http2Stream stream, List<KeyValuePair<string, string>> headers, bool transparentDecompression)
    {
        var status = int.Parse(headers.Find(static header => header.Key == ":status").Value, NumberStyles.None, CultureInfo.InvariantCulture);
        var hasBody = request.Method != HttpMethod.Head && status is not (204 or 304);
        if (!hasBody)
        {
            stream.Connection.CreditConnection(stream.Discard());
        }

        var response = ResponseFactory.Create(
            request,
            status,
            HttpVersion.Version20,
            null,
            headers.Where(static header => !header.Key.StartsWith(':')),
            hasBody ? new Http2ResponseBodyStream(stream) : null,
            transparentDecompression);
        stream.Response = response;
        return response;
    }

    private async Task WriteHeadersAsync(
        Http2Stream stream, List<KeyValuePair<string, string>> headers, bool endStream, Http2HeadersPriority? priority, CancellationToken cancellationToken)
    {
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!IsReusable)
            {
                throw new Http2RetryableException("The HTTP/2 connection is closing.");
            }

            // From here on the HPACK state advances, so the frames must be written in full: no cancellation.
            var block = _encoder.Encode(headers);
            stream.Id = _nextStreamId;
            _nextStreamId += 2;
            lock (_flowLock)
            {
                stream.SendWindow = _peerInitialWindow;
            }

            _streams[stream.Id] = stream;

            try
            {
                await _stream.WriteAsync(HeaderFrames(stream.Id, block, endStream, priority), CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is IOException or ObjectDisposedException)
            {
                Close(exception);
                throw new Http2RetryableException("Writing the request headers failed.", exception);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private byte[] HeaderFrames(int streamId, byte[] block, bool endStream, Http2HeadersPriority? headersPriority)
    {
        var maxFrameSize = Volatile.Read(ref _peerMaxFrameSize);
        byte[] priority = headersPriority is { } p
            ? Http2Frame.PriorityFields((int)p.DependencyStreamId, p.Exclusive, p.Weight)
            : [];

        var firstLength = Math.Min(block.Length, maxFrameSize - priority.Length);
        var flags = (byte)((endStream ? Http2Flags.EndStream : 0)
            | (priority.Length > 0 ? Http2Flags.Priority : 0)
            | (firstLength == block.Length ? Http2Flags.EndHeaders : 0));

        var frames = new List<byte>(block.Length + 64);
        frames.AddRange(Http2Frame.Create(Http2FrameType.Headers, flags, streamId, [.. priority, .. block.AsSpan(0, firstLength)]));
        for (var offset = firstLength; offset < block.Length;)
        {
            var length = Math.Min(block.Length - offset, maxFrameSize);
            var last = offset + length == block.Length;
            frames.AddRange(Http2Frame.Create(Http2FrameType.Continuation, last ? Http2Flags.EndHeaders : (byte)0, streamId, block.AsSpan(offset, length)));
            offset += length;
        }

        return [.. frames];
    }

    private async Task<int> ReserveWindowAsync(Http2Stream stream, int wanted, CancellationToken cancellationToken)
    {
        while (true)
        {
            Task changed;
            lock (_flowLock)
            {
                if (Volatile.Read(ref _closed) != 0)
                {
                    throw new IOException("The HTTP/2 connection is closed.");
                }

                if (stream.Error is { } error)
                {
                    throw new IOException("The server reset the stream while the request body was being sent.", error);
                }

                var available = (int)Math.Min(wanted, Math.Min(_connectionSendWindow, stream.SendWindow));
                if (available > 0)
                {
                    _connectionSendWindow -= available;
                    stream.SendWindow -= available;
                    return available;
                }

                changed = _flowChanged.Task;
            }

            await changed.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WriteFrameAsync(byte[] frame)
    {
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            await _stream.WriteAsync(frame, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or ObjectDisposedException)
        {
            Close(exception);
            throw new IOException("Writing to the HTTP/2 connection failed.", exception);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private void SendControl(byte[] frame)
    {
        _ = SendControlAsync(frame);

        async Task SendControlAsync(byte[] control)
        {
            try
            {
                await WriteFrameAsync(control).ConfigureAwait(false);
            }
            catch (IOException)
            {
                // The connection is already closing; nothing to tell the server.
            }
        }
    }

    private void CreditConnection(int bytes)
    {
        if (bytes <= 0 || Interlocked.Add(ref _connectionUnacknowledged, bytes) < _windowUpdateThreshold)
        {
            return;
        }

        var increment = Interlocked.Exchange(ref _connectionUnacknowledged, 0);
        if (increment > 0)
        {
            SendControl(Http2Frame.WindowUpdate(0, increment));
        }
    }

    private async Task ReadLoopAsync()
    {
        Exception failure;
        try
        {
            while (true)
            {
                if (await _reader.ReadAsync(_localMaxFrameSize, CancellationToken.None).ConfigureAwait(false) is not { } frame)
                {
                    failure = new IOException("The server closed the HTTP/2 connection.");
                    break;
                }

                await HandleFrameAsync(frame.Header, frame.Payload).ConfigureAwait(false);
            }
        }
        catch (Http2ConnectionException exception)
        {
            failure = exception;
            await TrySendGoAwayAsync(exception.Code).ConfigureAwait(false);
        }
        catch (HpackException exception)
        {
            failure = exception;
            await TrySendGoAwayAsync(Http2ErrorCode.CompressionError).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        Close(failure);
    }

    private async Task HandleFrameAsync(Http2FrameHeader header, ReadOnlyMemory<byte> payload)
    {
        if (_headerBlock is not null && header.Type != Http2FrameType.Continuation)
        {
            throw new Http2ConnectionException(Http2ErrorCode.ProtocolError, "Expected CONTINUATION.");
        }

        switch (header.Type)
        {
            case Http2FrameType.Data:
                OnData(header, payload);
                break;
            case Http2FrameType.Headers:
                RequireStream(header);
                BeginHeaderBlock(header, Unpad(header, payload, header.Has(Http2Flags.Priority) ? 5 : 0).Span, header.Has(Http2Flags.EndStream), pushPromisedStreamId: 0);
                break;
            case Http2FrameType.PushPromise:
                RequireStream(header);
                var promise = Unpad(header, payload, 4);
                var promised = BinaryPrimitives.ReadInt32BigEndian(payload.Span[(header.Has(Http2Flags.Padded) ? 1 : 0)..]) & int.MaxValue;
                BeginHeaderBlock(header, promise.Span, endStream: false, promised);
                break;
            case Http2FrameType.Continuation:
                if (_headerBlock is null || header.StreamId != _headerBlockStreamId)
                {
                    throw new Http2ConnectionException(Http2ErrorCode.ProtocolError, "Unexpected CONTINUATION.");
                }

                _headerBlock.AddRange(payload.Span);
                if (header.Has(Http2Flags.EndHeaders))
                {
                    EndHeaderBlock();
                }

                break;
            case Http2FrameType.Settings:
                await OnSettingsAsync(header, payload).ConfigureAwait(false);
                break;
            case Http2FrameType.Ping:
                if (header.Length != 8 || header.StreamId != 0)
                {
                    throw new Http2ConnectionException(Http2ErrorCode.FrameSizeError, "Malformed PING.");
                }

                if (!header.Has(Http2Flags.Ack))
                {
                    await WriteFrameAsync(Http2Frame.Create(Http2FrameType.Ping, Http2Flags.Ack, 0, payload.Span)).ConfigureAwait(false);
                }

                break;
            case Http2FrameType.GoAway:
                OnGoAway(header, payload.Span);
                break;
            case Http2FrameType.WindowUpdate:
                OnWindowUpdate(header, payload.Span);
                break;
            case Http2FrameType.RstStream:
                OnRstStream(header, payload.Span);
                break;
            default:
                // PRIORITY from the server and unknown frame types are ignored (RFC 9113 §5.5).
                break;
        }
    }

    private static void RequireStream(Http2FrameHeader header)
    {
        if (header.StreamId == 0)
        {
            throw new Http2ConnectionException(Http2ErrorCode.ProtocolError, $"{header.Type} on stream 0.");
        }
    }

    private static ReadOnlyMemory<byte> Unpad(Http2FrameHeader header, ReadOnlyMemory<byte> payload, int fixedFields)
    {
        var padding = 0;
        var offset = fixedFields;
        if (header.Has(Http2Flags.Padded))
        {
            if (payload.IsEmpty)
            {
                throw new Http2ConnectionException(Http2ErrorCode.ProtocolError, "Missing pad length.");
            }

            padding = payload.Span[0];
            offset++;
        }

        if (offset + padding > payload.Length)
        {
            throw new Http2ConnectionException(Http2ErrorCode.ProtocolError, "Padding exceeds the frame.");
        }

        return payload[offset..(payload.Length - padding)];
    }

    private void OnData(Http2FrameHeader header, ReadOnlyMemory<byte> payload)
    {
        RequireStream(header);
        var data = Unpad(header, payload, 0);
        CreditConnection(payload.Length - data.Length);

        _streams.TryGetValue(header.StreamId, out var stream);
        if (stream is null || !stream.OnData(data.Span))
        {
            CreditConnection(data.Length);
        }

        if (stream is not null && header.Has(Http2Flags.EndStream))
        {
            stream.OnRemoteEnd();
            RemoveStream(stream);
        }
    }

    private void BeginHeaderBlock(Http2FrameHeader header, ReadOnlySpan<byte> fragment, bool endStream, int pushPromisedStreamId)
    {
        _headerBlock = [.. fragment];
        _headerBlockStreamId = header.StreamId;
        _headerBlockEndStream = endStream;
        _pushPromisedStreamId = pushPromisedStreamId;
        if (header.Has(Http2Flags.EndHeaders))
        {
            EndHeaderBlock();
        }
    }

    private void EndHeaderBlock()
    {
        // Always decode: skipping a block would desynchronise the shared HPACK table.
        var headers = _decoder.Decode([.. _headerBlock!]);
        var streamId = _headerBlockStreamId;
        var endStream = _headerBlockEndStream;
        var promised = _pushPromisedStreamId;
        _headerBlock = null;
        _headerBlockStreamId = 0;

        if (promised != 0)
        {
            // Like OkHttp's default PushObserver: refuse every push.
            SendControl(Http2Frame.RstStream(promised, Http2ErrorCode.Cancel));
            return;
        }

        if (!_streams.TryGetValue(streamId, out var stream))
        {
            return;
        }

        try
        {
            stream.OnHeaders(headers);
        }
        catch (HttpIOException exception)
        {
            stream.Fail(exception);
            Reset(stream, Http2ErrorCode.ProtocolError);
            return;
        }

        if (endStream)
        {
            stream.OnRemoteEnd();
            RemoveStream(stream);
        }
    }

    private async Task OnSettingsAsync(Http2FrameHeader header, ReadOnlyMemory<byte> payload)
    {
        if (header.StreamId != 0)
        {
            throw new Http2ConnectionException(Http2ErrorCode.ProtocolError, "SETTINGS on a stream.");
        }

        if (header.Has(Http2Flags.Ack))
        {
            if (header.Length != 0)
            {
                throw new Http2ConnectionException(Http2ErrorCode.FrameSizeError, "SETTINGS ACK with a payload.");
            }

            return;
        }

        if (header.Length % 6 != 0)
        {
            throw new Http2ConnectionException(Http2ErrorCode.FrameSizeError, "SETTINGS payload is not a multiple of 6.");
        }

        int? headerTableSize = null;
        for (var offset = 0; offset < payload.Length; offset += 6)
        {
            var id = BinaryPrimitives.ReadUInt16BigEndian(payload.Span[offset..]);
            var value = BinaryPrimitives.ReadUInt32BigEndian(payload.Span[(offset + 2)..]);
            switch (id)
            {
                case Http2SettingId.HeaderTableSize:
                    headerTableSize = (int)Math.Min(value, int.MaxValue);
                    break;
                case Http2SettingId.MaxConcurrentStreams:
                    SetPeerMaxConcurrentStreams((int)Math.Min(value, int.MaxValue));
                    break;
                case Http2SettingId.InitialWindowSize:
                    SetPeerInitialWindow(value);
                    break;
                case Http2SettingId.MaxFrameSize:
                    if (value is < Http2Frame.DefaultMaxFrameSize or > Http2Frame.MaxAllowedFrameSize)
                    {
                        throw new Http2ConnectionException(Http2ErrorCode.ProtocolError, $"Invalid SETTINGS_MAX_FRAME_SIZE {value}.");
                    }

                    Volatile.Write(ref _peerMaxFrameSize, (int)value);
                    break;
            }
        }

        // The table size change and the ACK go out under the write lock, so no header block is encoded in between.
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (headerTableSize is { } size)
            {
                _encoder.SetMaxTableSize(size);
            }

            await _stream.WriteAsync(Http2Frame.Create(Http2FrameType.Settings, Http2Flags.Ack, 0, []), CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private void SetPeerInitialWindow(uint value)
    {
        if (value > int.MaxValue)
        {
            throw new Http2ConnectionException(Http2ErrorCode.FlowControlError, $"SETTINGS_INITIAL_WINDOW_SIZE {value} is too large.");
        }

        lock (_flowLock)
        {
            var delta = (int)value - _peerInitialWindow;
            _peerInitialWindow = (int)value;
            foreach (var stream in _streams.Values)
            {
                stream.SendWindow += delta;
            }

            SignalFlowLocked();
        }
    }

    private void OnGoAway(Http2FrameHeader header, ReadOnlySpan<byte> payload)
    {
        if (header.StreamId != 0 || payload.Length < 8)
        {
            throw new Http2ConnectionException(Http2ErrorCode.ProtocolError, "Malformed GOAWAY.");
        }

        var lastStreamId = BinaryPrimitives.ReadInt32BigEndian(payload) & int.MaxValue;
        var code = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(payload[4..]);
        _goingAway = true;
        Log.GoAway(_logger, Origin.Host, code, lastStreamId);

        foreach (var stream in _streams.Values.Where(stream => stream.Id > lastStreamId))
        {
            RemoveStream(stream);
            stream.Fail(new Http2RetryableException($"The server did not process the stream (GOAWAY {code})."));
        }

        FailSlotWaiters();
    }

    private void OnWindowUpdate(Http2FrameHeader header, ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 4)
        {
            throw new Http2ConnectionException(Http2ErrorCode.FrameSizeError, "Malformed WINDOW_UPDATE.");
        }

        var increment = BinaryPrimitives.ReadInt32BigEndian(payload) & int.MaxValue;
        _streams.TryGetValue(header.StreamId, out var stream);
        if (increment == 0)
        {
            if (header.StreamId == 0)
            {
                throw new Http2ConnectionException(Http2ErrorCode.ProtocolError, "WINDOW_UPDATE with a zero increment.");
            }

            if (stream is not null)
            {
                Reset(stream, Http2ErrorCode.ProtocolError);
            }

            return;
        }

        lock (_flowLock)
        {
            if (header.StreamId == 0)
            {
                _connectionSendWindow += increment;
                if (_connectionSendWindow > int.MaxValue)
                {
                    throw new Http2ConnectionException(Http2ErrorCode.FlowControlError, "Connection send window overflow.");
                }
            }
            else if (stream is not null)
            {
                stream.SendWindow += increment;
            }

            SignalFlowLocked();
        }
    }

    private void OnRstStream(Http2FrameHeader header, ReadOnlySpan<byte> payload)
    {
        RequireStream(header);
        if (payload.Length != 4)
        {
            throw new Http2ConnectionException(Http2ErrorCode.FrameSizeError, "Malformed RST_STREAM.");
        }

        if (!_streams.TryGetValue(header.StreamId, out var stream))
        {
            return;
        }

        var code = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(payload);
        RemoveStream(stream);
        stream.Fail(code == Http2ErrorCode.RefusedStream
            ? new Http2RetryableException("The server refused the stream.", refusedStream: true)
            : new HttpProtocolException((long)code, $"The server reset the stream ({code}).", null));
        SignalFlow();
    }

    private async Task TrySendGoAwayAsync(Http2ErrorCode code)
    {
        try
        {
            await WriteFrameAsync(Http2Frame.GoAway(0, code)).ConfigureAwait(false);
        }
        catch (IOException)
        {
            // Closing anyway.
        }
    }

    private void Close(Exception reason)
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }

        Log.Http2Closed(_logger, Origin.Host, reason);
        var error = new IOException("The HTTP/2 connection closed.", reason);
        foreach (var stream in _streams.Values)
        {
            RemoveStream(stream);
            stream.Fail(error);
        }

        FailSlotWaiters();
        SignalFlow();
        try
        {
            _stream.Dispose();
        }
        catch (IOException)
        {
            // Already broken.
        }
    }

    private async Task AcquireStreamSlotAsync(CancellationToken cancellationToken)
    {
        TaskCompletionSource waiter;
        lock (_slotLock)
        {
            if (!IsReusable)
            {
                throw new StaleConnectionException(new Http2RetryableException("The HTTP/2 connection is closing."));
            }

            if (_activeStreams < _peerMaxConcurrentStreams)
            {
                _activeStreams++;
                return;
            }

            waiter = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _slotWaiters.Enqueue(waiter);
        }

        try
        {
            await waiter.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (!waiter.TrySetCanceled(cancellationToken))
            {
                // Granted just as we gave up: hand the slot on.
                ReleaseStreamSlot();
            }

            throw;
        }
        catch (Http2RetryableException exception)
        {
            throw new StaleConnectionException(exception);
        }
    }

    private void ReleaseStreamSlot()
    {
        lock (_slotLock)
        {
            while (_slotWaiters.TryDequeue(out var waiter))
            {
                if (waiter.TrySetResult())
                {
                    return;
                }
            }

            if (--_activeStreams == 0)
            {
                _idleSince = Stopwatch.GetTimestamp();
            }
        }
    }

    private void SetPeerMaxConcurrentStreams(int value)
    {
        lock (_slotLock)
        {
            _peerMaxConcurrentStreams = value;
            while (_activeStreams < value && _slotWaiters.TryDequeue(out var waiter))
            {
                if (waiter.TrySetResult())
                {
                    _activeStreams++;
                }
            }
        }
    }

    private void FailSlotWaiters()
    {
        lock (_slotLock)
        {
            while (_slotWaiters.TryDequeue(out var waiter))
            {
                waiter.TrySetException(new Http2RetryableException("The HTTP/2 connection is closing."));
            }
        }
    }

    private bool RemoveStream(Http2Stream stream)
    {
        if (stream.Id == 0 || !_streams.TryRemove(stream.Id, out _))
        {
            return false;
        }

        ReleaseStreamSlot();
        return true;
    }

    private void ReleaseIfNeverOpened(Http2Stream stream)
    {
        if (stream.Id == 0)
        {
            ReleaseStreamSlot();
        }
    }

    private void SignalFlow()
    {
        lock (_flowLock)
        {
            SignalFlowLocked();
        }
    }

    private void SignalFlowLocked()
    {
        var changed = _flowChanged;
        _flowChanged = NewSignal();
        changed.TrySetResult();
    }

    private static TaskCompletionSource NewSignal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static uint LocalSetting(IReadOnlyList<Http2Setting> settings, ushort id, uint fallback)
    {
        for (var i = settings.Count - 1; i >= 0; i--)
        {
            if (settings[i].Id == id)
            {
                return settings[i].Value;
            }
        }

        return fallback;
    }

    private static byte[] Preface(Http2Profile profile)
    {
        var preface = new List<byte>(Http2Frame.ClientPreface.ToArray());
        if (profile.Preface.Count == 0 || profile.Preface[0] is not Http2SettingsFrame)
        {
            // The connection preface must start with SETTINGS.
            preface.AddRange(Http2Frame.Settings([]));
        }

        foreach (var frame in profile.Preface)
        {
            preface.AddRange(frame switch
            {
                Http2SettingsFrame settings => Http2Frame.Settings(settings.Settings.Select(static s => (s.Id, s.Value))),
                Http2WindowUpdateFrame update => Http2Frame.WindowUpdate(0, (int)update.Increment),
                Http2PriorityFrame priority => Http2Frame.Priority((int)priority.StreamId, (int)priority.DependencyStreamId, priority.Exclusive, priority.Weight),
                _ => throw new InvalidOperationException($"Unsupported preface frame {frame.GetType().Name}."),
            });
        }

        return [.. preface];
    }
}
