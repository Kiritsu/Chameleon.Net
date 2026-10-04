using System.Buffers.Binary;
using System.Globalization;
using Chameleon.Net.Http.Http2.Hpack;
using Chameleon.Net.Inspector.Analysis;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Server;

/// <summary>A minimal HTTP/2 server that keeps what Kestrel hides: every frame before the first request in order, SETTINGS in the order sent,
/// HEADERS priority fields and the pseudo-header order.</summary>
internal sealed class Http2Session(Stream stream, ConnectionCapture connection, Func<RequestCapture, InspectorResponse> respond)
{
    private const int MaxFrameSize = 16384;
    private const byte EndStream = 0x1;
    private const byte Ack = 0x1;
    private const byte EndHeaders = 0x4;
    private const byte Padded = 0x8;
    private const byte PriorityFlag = 0x20;

    private static ReadOnlySpan<byte> Preface => "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8;

    private readonly HpackDecoder _decoder = new(4096);
    private readonly HpackEncoder _encoder = new();
    private readonly List<FrameReport> _frames = [];
    private readonly List<string> _priorityFrames = [];
    private readonly List<Http2PrefaceFrame> _preface = [];
    private readonly Dictionary<int, OpenStream> _streams = [];
    private readonly List<PendingBody> _pending = [];
    private string? _settings;
    private string? _windowUpdate;
    private bool _sawHeaders;
    private long _connectionWindow = 65535;
    private int _peerInitialWindow = 65535;
    private int _peerMaxFrameSize = MaxFrameSize;
    private (int StreamId, byte Flags, PriorityReport? Priority, List<byte> Block)? _continuation;

    public async Task RunAsync(bool prefaceRead, CancellationToken cancellationToken)
    {
        if (!prefaceRead)
        {
            var preface = new byte[Preface.Length];
            await stream.ReadExactlyAsync(preface, cancellationToken);
            if (!preface.AsSpan().SequenceEqual(Preface))
            {
                throw new InvalidDataException("Not an HTTP/2 connection preface.");
            }
        }

        // SETTINGS_MAX_CONCURRENT_STREAMS = 100, like most servers.
        await WriteFrameAsync(4, 0, 0, [0, 3, 0, 0, 0, 100], cancellationToken);

        var header = new byte[9];
        var payload = new byte[MaxFrameSize];
        while (true)
        {
            if (await stream.ReadAtLeastAsync(header, header.Length, throwOnEndOfStream: false, cancellationToken) < header.Length)
            {
                return;
            }

            var length = (header[0] << 16) | (header[1] << 8) | header[2];
            var type = header[3];
            var flags = header[4];
            var streamId = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(5)) & int.MaxValue;
            if (length > MaxFrameSize)
            {
                throw new InvalidDataException($"{length}-byte frame exceeds SETTINGS_MAX_FRAME_SIZE.");
            }

            await stream.ReadExactlyAsync(payload.AsMemory(0, length), cancellationToken);
            if (!await HandleFrameAsync(type, flags, streamId, payload.AsSpan(0, length).ToArray(), cancellationToken))
            {
                return;
            }
        }
    }

    private async Task<bool> HandleFrameAsync(byte type, byte flags, int streamId, byte[] data, CancellationToken cancellationToken)
    {
        switch (type)
        {
            case 0: // DATA
                Record("DATA", streamId, flags, $"{data.Length} bytes");
                if (data.Length > 0)
                {
                    await WriteFrameAsync(8, 0, 0, UInt32(data.Length), cancellationToken);
                    await WriteFrameAsync(8, 0, streamId, UInt32(data.Length), cancellationToken);
                }

                if ((flags & EndStream) != 0 && _streams.TryGetValue(streamId, out var open))
                {
                    await CompleteAsync(streamId, open, cancellationToken);
                }

                break;

            case 1: // HEADERS
                var offset = 0;
                var padding = 0;
                if ((flags & Padded) != 0)
                {
                    padding = data[0];
                    offset = 1;
                }

                PriorityReport? priority = null;
                if ((flags & PriorityFlag) != 0)
                {
                    var dependency = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(offset));
                    priority = new PriorityReport((int)(dependency & int.MaxValue), data[offset + 4] + 1, (dependency & 0x8000_0000) != 0);
                    offset += 5;
                }

                _continuation = (streamId, flags, priority, [.. data.AsSpan(offset, data.Length - offset - padding)]);
                if ((flags & EndHeaders) != 0)
                {
                    await HeadersCompleteAsync(cancellationToken);
                }

                break;

            case 9: // CONTINUATION
                if (_continuation is not { } pending || pending.StreamId != streamId)
                {
                    throw new InvalidDataException("CONTINUATION without HEADERS.");
                }

                pending.Block.AddRange(data);
                if ((flags & EndHeaders) != 0)
                {
                    await HeadersCompleteAsync(cancellationToken);
                }

                break;

            case 2: // PRIORITY
                var priorityDependency = BinaryPrimitives.ReadUInt32BigEndian(data);
                var exclusive = (priorityDependency & 0x8000_0000) != 0;
                var weight = data[4] + 1;
                Record("PRIORITY", streamId, flags, $"depends on {priorityDependency & int.MaxValue}, weight {weight}{(exclusive ? ", exclusive" : "")}");
                if (!_sawHeaders)
                {
                    _priorityFrames.Add($"{streamId}:{(exclusive ? 1 : 0)}:{priorityDependency & int.MaxValue}:{weight}");
                    _preface.Add(new Http2PriorityFrame((uint)streamId, priorityDependency & int.MaxValue, (byte)(weight - 1), exclusive));
                }

                break;

            case 3: // RST_STREAM
                Record("RST_STREAM", streamId, flags, $"error {BinaryPrimitives.ReadUInt32BigEndian(data)}");
                _streams.Remove(streamId);
                _pending.RemoveAll(p => p.StreamId == streamId);
                break;

            case 4: // SETTINGS
                if ((flags & Ack) != 0)
                {
                    Record("SETTINGS", streamId, flags, null);
                    break;
                }

                var settings = new List<(ushort Id, uint Value)>();
                for (var i = 0; i + 6 <= data.Length; i += 6)
                {
                    settings.Add((BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(i)), BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(i + 2))));
                }

                Record("SETTINGS", streamId, flags, string.Join(", ", settings.Select(static s => $"{SettingName(s.Id)}={s.Value}")));
                if (!_sawHeaders)
                {
                    _settings ??= string.Join(';', settings.Select(static s => $"{s.Id}:{s.Value}"));
                    _preface.Add(new Http2SettingsFrame([.. settings.Select(static s => new Http2Setting(s.Id, s.Value))]));
                }

                foreach (var (id, value) in settings)
                {
                    ApplySetting(id, value);
                }

                await WriteFrameAsync(4, Ack, 0, [], cancellationToken);
                await FlushPendingAsync(cancellationToken);
                break;

            case 6: // PING
                Record("PING", streamId, flags, Convert.ToHexStringLower(data));
                if ((flags & Ack) == 0)
                {
                    await WriteFrameAsync(6, Ack, 0, data, cancellationToken);
                }

                break;

            case 7: // GOAWAY
                Record("GOAWAY", streamId, flags, $"last stream {BinaryPrimitives.ReadUInt32BigEndian(data) & int.MaxValue}, error {BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(4))}");
                return false;

            case 8: // WINDOW_UPDATE
                var increment = BinaryPrimitives.ReadUInt32BigEndian(data) & int.MaxValue;
                Record("WINDOW_UPDATE", streamId, flags, $"increment {increment}");
                if (streamId == 0)
                {
                    _connectionWindow += increment;
                    if (!_sawHeaders)
                    {
                        _windowUpdate ??= increment.ToString(CultureInfo.InvariantCulture);
                        _preface.Add(new Http2WindowUpdateFrame(increment));
                    }
                }
                else if (_streams.TryGetValue(streamId, out var updated))
                {
                    updated.SendWindow += increment;
                }

                await FlushPendingAsync(cancellationToken);
                break;

            default:
                Record(type == 0x10 ? "PRIORITY_UPDATE" : $"0x{type:x2}", streamId, flags, $"{data.Length} bytes");
                break;
        }

        return true;
    }

    private async Task HeadersCompleteAsync(CancellationToken cancellationToken)
    {
        var (streamId, flags, priority, block) = _continuation!.Value;
        _continuation = null;
        var trace = new List<HpackFieldTrace>();
        var fields = _decoder.Decode(block.ToArray(), trace);
        var pseudo = fields.Where(static f => f.Key.StartsWith(':')).Select(static f => f.Key).ToList();

        if (_streams.TryGetValue(streamId, out var existing))
        {
            // Trailers end the request.
            await CompleteAsync(streamId, existing, cancellationToken);
            return;
        }

        Record("HEADERS", streamId, flags, priority is null
            ? $"pseudo-headers {string.Join(',', pseudo.Select(ReportBuilder.PseudoHeaderLetter))}"
            : $"depends on {priority.DependsOn}, weight {priority.Weight}{(priority.Exclusive ? ", exclusive" : "")}; pseudo-headers {string.Join(',', pseudo.Select(ReportBuilder.PseudoHeaderLetter))}");

        if (!_sawHeaders)
        {
            _sawHeaders = true;
            var akamai = string.Join('|',
                _settings ?? "",
                _windowUpdate ?? "00",
                _priorityFrames.Count == 0 ? "0" : string.Join(',', _priorityFrames),
                string.Join(',', pseudo.Where(static p => p is ":method" or ":authority" or ":scheme" or ":path").Select(ReportBuilder.PseudoHeaderLetter)));
            connection.Http2 = new Http2ConnectionCapture(akamai, [.. _frames], streamId, [.. _preface], pseudo);
        }

        string? Pseudo(string name) => fields.FirstOrDefault(f => f.Key == name).Value;
        var request = new RequestCapture(
            "2",
            Pseudo(":method") ?? "",
            Pseudo(":path") ?? "",
            Pseudo(":authority"),
            [.. fields.Where(static f => !f.Key.StartsWith(':')).Select(static f => new HeaderField(f.Key, f.Value))],
            pseudo,
            WebSocket: false,
            streamId,
            priority,
            HpackReports(fields, trace));
        connection.AddHttp2Request(request);

        var open = new OpenStream(request) { SendWindow = _peerInitialWindow };
        _streams[streamId] = open;
        if ((flags & EndStream) != 0)
        {
            await CompleteAsync(streamId, open, cancellationToken);
        }
    }

    private async Task CompleteAsync(int streamId, OpenStream open, CancellationToken cancellationToken)
    {
        if (open.Responded)
        {
            return;
        }

        open.Responded = true;
        var response = respond(open.Request);
        var body = open.Request.Method == "HEAD" ? [] : response.Body;
        var block = _encoder.Encode(
        [
            new(":status", response.Status.ToString(CultureInfo.InvariantCulture)),
            new("content-type", response.ContentType),
            new("content-length", response.Body.Length.ToString(CultureInfo.InvariantCulture)),
            new("cache-control", "no-store"),
            new("access-control-allow-origin", "*"),
            .. (response.Headers ?? []).Select(static h => new KeyValuePair<string, string>(h.Key.ToLowerInvariant(), h.Value)),
        ]);
        await WriteFrameAsync(1, (byte)(EndHeaders | (body.Length == 0 ? EndStream : 0)), streamId, block, cancellationToken);
        if (body.Length == 0)
        {
            _streams.Remove(streamId);
            return;
        }

        _pending.Add(new PendingBody(streamId, body));
        await FlushPendingAsync(cancellationToken);
    }

    private async Task FlushPendingAsync(CancellationToken cancellationToken)
    {
        foreach (var pending in _pending.ToList())
        {
            if (!_streams.TryGetValue(pending.StreamId, out var open))
            {
                _pending.Remove(pending);
                continue;
            }

            while (!pending.Remaining.IsEmpty)
            {
                var chunk = (int)Math.Min(Math.Min(pending.Remaining.Length, _peerMaxFrameSize), Math.Min(_connectionWindow, open.SendWindow));
                if (chunk <= 0)
                {
                    break;
                }

                var last = chunk == pending.Remaining.Length;
                await WriteFrameAsync(0, last ? EndStream : (byte)0, pending.StreamId, pending.Remaining[..chunk].ToArray(), cancellationToken);
                pending.Remaining = pending.Remaining[chunk..];
                _connectionWindow -= chunk;
                open.SendWindow -= chunk;
            }

            if (pending.Remaining.IsEmpty)
            {
                _pending.Remove(pending);
                _streams.Remove(pending.StreamId);
            }
        }
    }

    private void ApplySetting(ushort id, uint value)
    {
        switch (id)
        {
            case 1:
                _encoder.SetMaxTableSize((int)Math.Min(value, int.MaxValue));
                break;
            case 4:
                var delta = (long)value - _peerInitialWindow;
                _peerInitialWindow = (int)value;
                foreach (var open in _streams.Values)
                {
                    open.SendWindow += delta;
                }

                break;
            case 5:
                _peerMaxFrameSize = (int)value;
                break;
        }
    }

    private void Record(string type, int streamId, byte flags, string? detail)
    {
        if (_sawHeaders)
        {
            return;
        }

        var names = new List<string>();
        if (type is "DATA" or "HEADERS" && (flags & EndStream) != 0)
        {
            names.Add("END_STREAM");
        }

        if (type is "SETTINGS" or "PING" && (flags & Ack) != 0)
        {
            names.Add("ACK");
        }

        if (type is "HEADERS" or "CONTINUATION" && (flags & EndHeaders) != 0)
        {
            names.Add("END_HEADERS");
        }

        if (type is "DATA" or "HEADERS" && (flags & Padded) != 0)
        {
            names.Add("PADDED");
        }

        if (type == "HEADERS" && (flags & PriorityFlag) != 0)
        {
            names.Add("PRIORITY");
        }

        _frames.Add(new FrameReport(type, streamId, names.Count == 0 ? null : string.Join('|', names), detail));
    }

    private async Task WriteFrameAsync(byte type, byte flags, int streamId, byte[] payload, CancellationToken cancellationToken)
    {
        var frame = new byte[9 + payload.Length];
        frame[0] = (byte)(payload.Length >> 16);
        frame[1] = (byte)(payload.Length >> 8);
        frame[2] = (byte)payload.Length;
        frame[3] = type;
        frame[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(frame.AsSpan(5), streamId);
        payload.CopyTo(frame, 9);
        await stream.WriteAsync(frame, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static byte[] UInt32(int value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(bytes, value);
        return bytes;
    }

    private static string SettingName(ushort id) => id switch
    {
        1 => "HEADER_TABLE_SIZE",
        2 => "ENABLE_PUSH",
        3 => "MAX_CONCURRENT_STREAMS",
        4 => "INITIAL_WINDOW_SIZE",
        5 => "MAX_FRAME_SIZE",
        6 => "MAX_HEADER_LIST_SIZE",
        8 => "ENABLE_CONNECT_PROTOCOL",
        9 => "NO_RFC7540_PRIORITIES",
        _ => id.ToString(CultureInfo.InvariantCulture),
    };

    private static List<HpackFieldReport> HpackReports(List<KeyValuePair<string, string>> fields, List<HpackFieldTrace> trace)
    {
        var reports = new List<HpackFieldReport>(trace.Count);
        var field = 0;
        foreach (var entry in trace)
        {
            reports.Add(entry.Representation switch
            {
                HpackRepresentation.SizeUpdate => new HpackFieldReport(null, entry.Representation, entry.Index),
                HpackRepresentation.Indexed => new HpackFieldReport(fields[field++].Key, entry.Representation, entry.Index),
                _ => new HpackFieldReport(fields[field++].Key, entry.Representation, entry.Index == 0 ? null : entry.Index, entry.ValueHuffman, entry.NameHuffman),
            });
        }

        return reports;
    }

    private sealed class OpenStream(RequestCapture request)
    {
        public RequestCapture Request { get; } = request;
        public long SendWindow { get; set; }
        public bool Responded { get; set; }
    }

    private sealed class PendingBody(int streamId, byte[] body)
    {
        public int StreamId { get; } = streamId;
        public ReadOnlyMemory<byte> Remaining { get; set; } = body;
    }
}

/// <param name="Headers">Extra response headers (Set-Cookie for the capture page).</param>
internal sealed record InspectorResponse(int Status, string ContentType, byte[] Body, IReadOnlyList<KeyValuePair<string, string>>? Headers = null);
