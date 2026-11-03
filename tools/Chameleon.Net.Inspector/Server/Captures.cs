using System.Net;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Inspector.Analysis;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Tls;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Server;

/// <summary>What one connection showed before and around its requests.</summary>
internal sealed class ConnectionCapture(int id, IPEndPoint remote)
{
    /// <summary>Enough for a capture's downloads many times over; a client flooding frames can't grow a connection past it.</summary>
    public const int MaxHttp2Events = 1000;

    private readonly List<Http2EventReport> _http2Events = [];
    private int _reportedHttp2Events;
    private int _requests;

    public int Id { get; } = id;
    public IPEndPoint Remote { get; } = remote;
    public ClientHelloDetails? Hello { get; set; }
    public TlsFingerprint? Fingerprint { get; set; }
    public ushort RecordVersion { get; set; }
    public int HelloLength { get; set; }
    public ExtensionOrderReport? ExtensionOrder { get; set; }
    public string? TlsVersion { get; set; }
    public string? CipherSuite { get; set; }
    public string? Alpn { get; set; }
    public Http2ConnectionCapture? Http2 { get; set; }

    public int NextRequest() => Interlocked.Increment(ref _requests);

    public void AddHttp2Event(Http2EventReport frame)
    {
        lock (_http2Events)
        {
            if (_http2Events.Count < MaxHttp2Events)
            {
                _http2Events.Add(frame);
            }
        }
    }

    /// <summary>Every frame recorded after the first request.</summary>
    public List<Http2EventReport> Http2Events()
    {
        lock (_http2Events)
        {
            return [.. _http2Events];
        }
    }

    /// <summary>The frames recorded since the previous call, for the next report.</summary>
    public List<Http2EventReport> TakeUnreportedHttp2Events()
    {
        lock (_http2Events)
        {
            var unreported = _http2Events[_reportedHttp2Events..];
            _reportedHttp2Events = _http2Events.Count;
            return unreported;
        }
    }
}

/// <param name="Frames">Everything before the first HEADERS, then that HEADERS frame.</param>
/// <param name="Preface">SETTINGS, connection WINDOW_UPDATE and PRIORITY frames before the first HEADERS, in order, as profile data.</param>
/// <param name="PseudoHeaders">The first request's pseudo-header names in order.</param>
internal sealed record Http2ConnectionCapture(
    string Akamai,
    IReadOnlyList<FrameReport> Frames,
    int FirstStreamId,
    IReadOnlyList<Http2PrefaceFrame> Preface,
    IReadOnlyList<string> PseudoHeaders);

/// <param name="Version">"1.1", "1.0" or "2".</param>
/// <param name="Headers">Regular headers in the order and spelling received.</param>
/// <param name="PseudoHeaders">HTTP/2 pseudo-header names in the order received.</param>
/// <param name="Hpack">HTTP/2: how each header block field was encoded.</param>
/// <param name="HpackDifferences">HTTP/2: per set of HPACK rules, the fields an encoder following them, fed this connection's header blocks
/// in order, encodes differently.</param>
internal sealed record RequestCapture(
    string Version,
    string Method,
    string Path,
    string? Authority,
    IReadOnlyList<HeaderField> Headers,
    IReadOnlyList<string> PseudoHeaders,
    bool WebSocket,
    int StreamId = 0,
    PriorityReport? Priority = null,
    IReadOnlyList<HpackFieldReport>? Hpack = null,
    IReadOnlyDictionary<HpackIndexing, List<HpackDifference>>? HpackDifferences = null)
{
    public string? Header(string name) => Headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;
}
