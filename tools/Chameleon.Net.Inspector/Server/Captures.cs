using System.Net;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Tls;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Server;

/// <summary>What one connection showed before and around its requests.</summary>
internal sealed class ConnectionCapture(int id, IPEndPoint remote)
{
    private readonly List<RequestCapture> _http2Requests = [];
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

    /// <summary>Records an HTTP/2 request when its header block is decoded, so header blocks can be replayed in the client's order.</summary>
    public void AddHttp2Request(RequestCapture request)
    {
        lock (_http2Requests)
        {
            _http2Requests.Add(request);
        }
    }

    /// <summary>The HTTP/2 requests whose header blocks arrived up to and including this one's, in order; all of them when it is null.</summary>
    public List<RequestCapture> Http2RequestsThrough(RequestCapture? request = null)
    {
        lock (_http2Requests)
        {
            var index = request is null ? _http2Requests.Count - 1 : _http2Requests.FindIndex(r => ReferenceEquals(r, request));
            return index < 0 ? [] : _http2Requests[..(index + 1)];
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
    IReadOnlyList<HpackFieldReport>? Hpack = null)
{
    public string? Header(string name) => Headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;
}
