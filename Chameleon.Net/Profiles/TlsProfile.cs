namespace Chameleon.Net.Profiles;

/// <summary>ClientHello shape. Order of <see cref="CipherSuites"/> and <see cref="Extensions"/> is the fingerprint.</summary>
public sealed record TlsProfile(
    IReadOnlyList<ushort> CipherSuites,
    IReadOnlyList<TlsExtension> Extensions,
    ExtensionShufflePolicy Shuffle,
    GreasePlacement Grease);

public enum ExtensionShufflePolicy
{
    None,
    /// <summary>Chrome ≥110: shuffle everything except GREASE (pinned first/last), padding and pre_shared_key (pinned last).</summary>
    Chrome,
}

[Flags]
public enum GreasePlacement
{
    None = 0,
    CipherSuites = 1,
    FirstExtension = 2,
    LastExtension = 4,
    SupportedGroups = 8,
    KeyShare = 16,
    SupportedVersions = 32,
}
