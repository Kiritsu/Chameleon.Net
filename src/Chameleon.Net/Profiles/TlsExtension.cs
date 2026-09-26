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

/// <summary>ALPS. Chrome moved from the original codepoint 17513 to 17613 (Chrome 131+).</summary>
public sealed record ApplicationSettingsExtension(IReadOnlyList<string> Protocols, ushort Codepoint = 17513) : TlsExtension(Codepoint);

/// <summary>GREASE ECH (an outer ECH extension with random contents); real ECH is out of scope.</summary>
/// <param name="AeadIds">HPKE AEADs to pick from per connection. Null: AES-128-GCM only (BoringSSL). Firefox (NSS) picks AES-128-GCM or ChaCha20-Poly1305.</param>
/// <param name="PayloadLengths">Payload lengths to pick from per connection, AEAD tag included. Null: 144, 176, 208 or 240 (BoringSSL).
/// Firefox always sends 240.</param>
public sealed record EncryptedClientHelloGreaseExtension(IReadOnlyList<ushort>? AeadIds = null, IReadOnlyList<int>? PayloadLengths = null)
    : TlsExtension(65037);

public sealed record RenegotiationInfoExtension() : TlsExtension(65281);

/// <summary>Placeholder; the concrete GREASE value is drawn at build time. <paramref name="Body"/> is sent as-is: BoringSSL sends its first GREASE extension empty and its second with one zero byte.</summary>
public sealed record GreaseExtension(ReadOnlyMemory<byte> Body = default) : TlsExtension(0x0A0A);

public sealed record RawExtension(ushort Type, ReadOnlyMemory<byte> Body) : TlsExtension(Type);
