namespace Chameleon.Net.Profiles;

/// <summary>Akamai-style HTTP/2 fingerprint: the ordered connection preface plus how HEADERS frames are shaped.</summary>
/// <param name="HeadersPriorityOverrides">Per request kind, replacing <paramref name="HeadersPriority"/> (Chrome derives the weight
/// from the request's urgency: 256 for navigations, 220 for fetch()).</param>
/// <param name="FirstStreamId">Stream id of the first request on a connection (odd). Firefox starts at 3; everyone else at 1.
/// Preface PRIORITY frames push it further: requests never reuse a stream they name.</param>
/// <param name="Hpack">How header blocks are encoded. Null: OkHttp's way.</param>
public sealed record Http2Profile(
    IReadOnlyList<Http2PrefaceFrame> Preface,
    IReadOnlyList<PseudoHeader> PseudoHeaderOrder,
    Http2HeadersPriority? HeadersPriority,
    IReadOnlyDictionary<RequestKind, Http2HeadersPriority>? HeadersPriorityOverrides = null,
    uint FirstStreamId = 1,
    HpackProfile? Hpack = null)
{
    public Http2HeadersPriority? PriorityFor(RequestKind kind) =>
        HeadersPriorityOverrides is not null && HeadersPriorityOverrides.TryGetValue(kind, out var priority) ? priority : HeadersPriority;
}

/// <summary>Header block encoding choices a server can see in the HPACK representation.</summary>
/// <param name="SplitCookies">Send each cookie as its own <c>cookie</c> field (RFC 9113 §8.2.3), as Chrome and Safari do, so each one is
/// indexed separately. OkHttp sends the Cookie header as one field.</param>
/// <param name="Indexing">Which fields are indexed, and how.</param>
public sealed record HpackProfile(bool SplitCookies = false, HpackIndexing Indexing = HpackIndexing.OkHttp);

/// <summary>An HPACK encoder's indexing rules.</summary>
public enum HpackIndexing
{
    /// <summary>OkHttp's encoder, which Chrome matches: every regular field is indexed incrementally, :path and :method's other values
    /// are literals without indexing, and only :method, :path and :scheme are looked up in the static table with their value.</summary>
    OkHttp,

    /// <summary>nghttp2's encoder, which Safari matches: authorization and cookies under 20 bytes are never indexed; :path,
    /// content-length, etag, if-modified-since, if-none-match, location, age and set-cookie are literals without indexing; the whole
    /// static table is matched with values.</summary>
    Nghttp2,
}

public abstract record Http2PrefaceFrame;

public sealed record Http2SettingsFrame(IReadOnlyList<Http2Setting> Settings) : Http2PrefaceFrame;

public readonly record struct Http2Setting(ushort Id, uint Value);

public sealed record Http2WindowUpdateFrame(uint Increment) : Http2PrefaceFrame;

/// <summary>Sent on an idle stream before any request (Firefox's grouping nodes); requests then use the next free odd stream id.
/// <paramref name="Weight"/> is the wire value, i.e. weight − 1 (Wireshark shows it as-is; the Akamai fingerprint shows it + 1).</summary>
public sealed record Http2PriorityFrame(uint StreamId, uint DependencyStreamId, byte Weight, bool Exclusive) : Http2PrefaceFrame;

/// <summary>Priority fields carried on every request HEADERS frame. <paramref name="Weight"/> is the wire value, i.e. weight − 1 (Chrome's 256 is 255).</summary>
public readonly record struct Http2HeadersPriority(uint DependencyStreamId, byte Weight, bool Exclusive);

public enum PseudoHeader
{
    Method,
    Authority,
    Scheme,
    Path,
}
