namespace Chameleon.Net.Profiles;

/// <summary>One ClientHello extension, in emission order. Typed variants carry the data the handshake logic needs; anything else is <see cref="RawExtension"/>.</summary>
public abstract record TlsExtension(ushort Type);

public sealed record ServerNameExtension() : TlsExtension(0);

public sealed record StatusRequestExtension() : TlsExtension(5);

public sealed record SupportedGroupsExtension(IReadOnlyList<ushort> Groups) : TlsExtension(10);

public sealed record EcPointFormatsExtension(IReadOnlyList<byte> Formats) : TlsExtension(11);

public sealed record SignatureAlgorithmsExtension(IReadOnlyList<ushort> Schemes) : TlsExtension(13);

public sealed record AlpnExtension(IReadOnlyList<string> Protocols) : TlsExtension(16);

public sealed record SignedCertificateTimestampExtension() : TlsExtension(18);

public sealed record PaddingExtension(int TargetClientHelloLength) : TlsExtension(21);

public sealed record ExtendedMasterSecretExtension() : TlsExtension(23);

public sealed record CompressCertificateExtension(IReadOnlyList<ushort> Algorithms) : TlsExtension(27);

public sealed record RecordSizeLimitExtension(ushort Limit) : TlsExtension(28);

public sealed record DelegatedCredentialsExtension(IReadOnlyList<ushort> Schemes) : TlsExtension(34);

public sealed record SessionTicketExtension() : TlsExtension(35);

public sealed record SupportedVersionsExtension(IReadOnlyList<ushort> Versions) : TlsExtension(43);

public sealed record PskKeyExchangeModesExtension(IReadOnlyList<byte> Modes) : TlsExtension(45);

/// <summary>Groups for which a key_share entry is generated; a subset of <see cref="SupportedGroupsExtension.Groups"/>.</summary>
public sealed record KeyShareExtension(IReadOnlyList<ushort> Groups) : TlsExtension(51);

public sealed record ApplicationSettingsExtension(IReadOnlyList<string> Protocols) : TlsExtension(17513);

/// <summary>GREASE ECH as sent by Chrome; real ECH is out of scope.</summary>
public sealed record EncryptedClientHelloGreaseExtension() : TlsExtension(65037);

public sealed record RenegotiationInfoExtension() : TlsExtension(65281);

/// <summary>Placeholder; the concrete GREASE value is drawn at build time.</summary>
public sealed record GreaseExtension() : TlsExtension(0x0A0A);

public sealed record RawExtension(ushort Type, ReadOnlyMemory<byte> Body) : TlsExtension(Type);
