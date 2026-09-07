namespace Chameleon.Net.Fingerprints;

/// <summary>Fields of a ClientHello that fingerprint algorithms consume, in wire order.</summary>
public sealed record ParsedClientHello(
    ushort RecordVersion,
    ushort HandshakeVersion,
    IReadOnlyList<ushort> CipherSuites,
    IReadOnlyList<ushort> ExtensionTypes,
    IReadOnlyList<ushort> SupportedGroups,
    IReadOnlyList<byte> EcPointFormats,
    IReadOnlyList<ushort> SignatureAlgorithms,
    IReadOnlyList<ushort> SupportedVersions,
    IReadOnlyList<string> Alpn,
    bool HasServerName);
