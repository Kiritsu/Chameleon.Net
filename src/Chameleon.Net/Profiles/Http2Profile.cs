namespace Chameleon.Net.Profiles;

/// <summary>Akamai-style HTTP/2 fingerprint: the ordered connection preface plus how HEADERS frames are shaped.</summary>
public sealed record Http2Profile(
    IReadOnlyList<Http2PrefaceFrame> Preface,
    IReadOnlyList<PseudoHeader> PseudoHeaderOrder,
    Http2HeadersPriority? HeadersPriority);

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
