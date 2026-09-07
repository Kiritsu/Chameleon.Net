namespace Chameleon.Net.Profiles;

/// <summary>Akamai-style HTTP/2 fingerprint: the ordered connection preface plus how HEADERS frames are shaped.</summary>
public sealed record Http2Profile(
    IReadOnlyList<Http2PrefaceFrame> Preface,
    IReadOnlyList<PseudoHeader> PseudoHeaderOrder,
    Http2HeadersPriority? HeadersPriority);

public abstract record Http2PrefaceFrame;

public sealed record Http2SettingsFrame(IReadOnlyList<Http2Setting> Settings) : Http2PrefaceFrame;

public sealed record Http2Setting(ushort Id, uint Value);

public sealed record Http2WindowUpdateFrame(uint Increment) : Http2PrefaceFrame;

public sealed record Http2PriorityFrame(uint StreamId, uint DependencyStreamId, byte Weight, bool Exclusive) : Http2PrefaceFrame;

public sealed record Http2HeadersPriority(uint DependencyStreamId, byte Weight, bool Exclusive);

public enum PseudoHeader
{
    Method,
    Authority,
    Scheme,
    Path,
}
