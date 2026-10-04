using Chameleon.Net.Http.Http2.Hpack;

namespace Chameleon.Net.Inspector.Reports;

/// <summary>What the inspector saw of one request (or of a TLS handshake that never got to one), as returned to the client.</summary>
internal sealed record InspectionReport(
    ConnectionReport Connection,
    TlsReport? Tls,
    HttpReport? Http,
    ClientReport Client,
    IReadOnlyList<Finding> Findings,
    Verdict Verdict);

/// <param name="Request">1 for the first request on the connection.</param>
/// <param name="Error">Why the connection ended before a request (for example the client rejected the certificate).</param>
internal sealed record ConnectionReport(int Id, int Request, string Remote, bool Tls, string? TlsVersion, string? CipherSuite, string? Alpn, string? Error = null);

internal sealed record TlsReport(
    string Ja3,
    string Ja3Hash,
    string Ja4,
    string Ja4Raw,
    string RecordVersion,
    string LegacyVersion,
    int HelloLength,
    int SessionIdLength,
    string? ServerName,
    IReadOnlyList<string> Alpn,
    IReadOnlyList<string> CipherSuites,
    IReadOnlyList<ExtensionReport> Extensions,
    IReadOnlyList<string> SupportedGroups,
    IReadOnlyList<string> KeyShares,
    IReadOnlyList<string> SignatureAlgorithms,
    IReadOnlyList<string> SupportedVersions,
    IReadOnlyList<int> EcPointFormats,
    IReadOnlyList<string> PskKeyExchangeModes,
    IReadOnlyList<string> CertificateCompression,
    AlpsReport? ApplicationSettings,
    EchReport? EncryptedClientHello,
    int? RecordSizeLimit,
    IReadOnlyList<string> DelegatedCredentials,
    int? Padding,
    PskReport? PreSharedKey,
    bool EarlyData,
    GreaseReport Grease,
    ExtensionOrderReport ExtensionOrder);

internal sealed record ExtensionReport(int Type, string Name, int Length);

internal sealed record AlpsReport(int Codepoint, IReadOnlyList<string> Protocols);

/// <summary>A server without ECH keys can't tell GREASE ECH from real ECH; the sizes are what identify the client.</summary>
internal sealed record EchReport(string Kdf, string Aead, int ConfigId, int EncLength, int PayloadLength);

internal sealed record PskReport(IReadOnlyList<int> IdentityLengths, int Binders);

/// <param name="ExtensionPositions">Zero-based positions of GREASE extensions in the extension list.</param>
internal sealed record GreaseReport(
    bool CipherSuites,
    IReadOnlyList<int> ExtensionPositions,
    bool SupportedGroups,
    bool KeyShare,
    bool SupportedVersions,
    bool SignatureAlgorithms);

/// <summary>Extension orders seen from this address with the same ClientHello (SNI, ALPN and PSK aside): Chrome shuffles on every connection,
/// other clients never do.</summary>
internal sealed record ExtensionOrderReport(int Connections, int DistinctOrders);

internal sealed record HttpReport(
    string Version,
    string Method,
    string Path,
    string? Authority,
    IReadOnlyList<HeaderField> Headers,
    string Ja4H,
    string Ja4HRaw,
    bool WebSocket,
    Http2Report? Http2);

internal sealed record HeaderField(string Name, string Value);

/// <param name="Frames">What the client sent before its first request, then that request's HEADERS.</param>
/// <param name="Priority">This request's HEADERS priority, if the frame carried one.</param>
/// <param name="Hpack">How each field of this request's header block was encoded, in wire order.</param>
/// <param name="Events">Frames the client sent on the connection after its first request, since the previous report on it.</param>
internal sealed record Http2Report(
    string Akamai,
    string AkamaiHash,
    IReadOnlyList<FrameReport> Frames,
    int FirstStreamId,
    int StreamId,
    PriorityReport? Priority,
    string PseudoHeaderOrder,
    IReadOnlyList<HpackFieldReport>? Hpack = null,
    IReadOnlyList<Http2EventReport>? Events = null);

/// <summary>An HTTP/2 connection once closed: every frame it carried after its first request, whether or not a later report showed them.</summary>
internal sealed record ConnectionLogReport(int Id, string Remote, string? Alpn, string Akamai, IReadOnlyList<Http2EventReport> Http2Events);

/// <summary>A frame received after the connection's first request, or CLOSED when the client closed the connection.</summary>
/// <param name="At">Milliseconds since the connection's preface.</param>
/// <param name="Value">WINDOW_UPDATE: the increment. RST_STREAM and GOAWAY: the error code. PING: 1 for an ACK.</param>
/// <param name="StreamDataSent">DATA payload bytes the inspector had sent on the frame's stream when it arrived (stream frames only).</param>
/// <param name="ConnectionDataSent">DATA payload bytes the inspector had sent on the connection when it arrived.</param>
internal sealed record Http2EventReport(double At, string Type, int StreamId, string? Flags, long? Value, long? StreamDataSent, long ConnectionDataSent);

/// <param name="Name">Null for a dynamic table size update.</param>
/// <param name="Index">Indexed fields: the entry (static up to 61, dynamic above). Literals: the name's index, null for a new name.
/// Size updates: the new size.</param>
/// <param name="Huffman">Literals: the value was Huffman-coded.</param>
/// <param name="NameHuffman">Literals with a new name: the name was Huffman-coded.</param>
internal sealed record HpackFieldReport(string? Name, HpackRepresentation Representation, int? Index, bool Huffman = false, bool NameHuffman = false);

internal sealed record FrameReport(string Type, int StreamId, string? Flags, string? Detail);

/// <param name="Weight">1–256, i.e. the wire value + 1, as in the Akamai fingerprint.</param>
internal sealed record PriorityReport(int DependsOn, int Weight, bool Exclusive);

internal sealed record ClientReport(
    UserAgentReport? UserAgent,
    ClientFamily TlsFamily,
    string TlsFamilyReason,
    IReadOnlyList<string> TlsMatches,
    ClientFamily? Http2Family,
    IReadOnlyList<string> Http2Matches);

internal sealed record UserAgentReport(string Raw, string Product, ClientFamily Family, int? MajorVersion, string? Platform, bool Mobile);

internal sealed record Finding(Severity Severity, string Layer, string Id, string Message);

/// <summary>The stack a client is built on, which decides its fingerprint: every Chromium-based browser shares one, every iOS browser uses WebKit's.</summary>
internal enum ClientFamily
{
    Unknown,
    Chromium,
    Firefox,
    Safari,
    OkHttp,

    /// <summary>curl, python-requests, Go, ... declaring themselves in the User-Agent.</summary>
    Tool,
}

internal enum Severity
{
    Info,
    Low,
    Medium,
    High,
}

/// <summary>A heuristic summary of the findings, not a CDN's actual decision.</summary>
internal enum Verdict
{
    Consistent,
    Suspicious,
    Inconsistent,
}
