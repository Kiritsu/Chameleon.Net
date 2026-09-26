namespace Chameleon.Net.Profiles;

/// <summary>ClientHello shape. Order of <see cref="CipherSuites"/> and <see cref="Extensions"/> is the fingerprint.
/// GREASE extensions are positioned by placing <see cref="GreaseExtension"/> entries in the list; <see cref="Grease"/> covers the lists inside other fields.</summary>
public sealed record TlsProfile(
    IReadOnlyList<ushort> CipherSuites,
    IReadOnlyList<TlsExtension> Extensions,
    ExtensionShufflePolicy Shuffle,
    GreasePlacement Grease);

public enum ExtensionShufflePolicy
{
    None,
    /// <summary>Chrome ≥110: shuffle everything except leading GREASE and trailing GREASE/padding entries.</summary>
    Chrome,
}

[Flags]
public enum GreasePlacement
{
    None = 0,
    CipherSuites = 1,
    SupportedGroups = 2,
    KeyShare = 4,
    SupportedVersions = 8,

    /// <summary>Chrome 13x+ also leads signature_algorithms with a GREASE value.</summary>
    SignatureAlgorithms = 16,
}
