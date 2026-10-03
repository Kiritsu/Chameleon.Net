using System.Collections.Frozen;
using System.Globalization;

namespace Chameleon.Net.Inspector.Tls;

/// <summary>IANA names for the code points browsers and common TLS libraries send, for readable reports.</summary>
internal static class TlsNames
{
    private static readonly FrozenDictionary<ushort, string> CipherSuites = new Dictionary<ushort, string>
    {
        [0x1301] = "TLS_AES_128_GCM_SHA256",
        [0x1302] = "TLS_AES_256_GCM_SHA384",
        [0x1303] = "TLS_CHACHA20_POLY1305_SHA256",
        [0xC02B] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        [0xC02F] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        [0xC02C] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        [0xC030] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        [0xCCA9] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        [0xCCA8] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        [0xCCAA] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        [0xC009] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        [0xC00A] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        [0xC013] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        [0xC014] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        [0xC023] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        [0xC024] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        [0xC027] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        [0xC028] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        [0x009C] = "TLS_RSA_WITH_AES_128_GCM_SHA256",
        [0x009D] = "TLS_RSA_WITH_AES_256_GCM_SHA384",
        [0x009E] = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        [0x009F] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        [0x002F] = "TLS_RSA_WITH_AES_128_CBC_SHA",
        [0x0035] = "TLS_RSA_WITH_AES_256_CBC_SHA",
        [0x003C] = "TLS_RSA_WITH_AES_128_CBC_SHA256",
        [0x003D] = "TLS_RSA_WITH_AES_256_CBC_SHA256",
        [0x0033] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        [0x0039] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        [0x000A] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        [0x00FF] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    }.ToFrozenDictionary();

    private static readonly FrozenDictionary<ushort, string> Extensions = new Dictionary<ushort, string>
    {
        [0] = "server_name",
        [1] = "max_fragment_length",
        [5] = "status_request",
        [10] = "supported_groups",
        [11] = "ec_point_formats",
        [13] = "signature_algorithms",
        [14] = "use_srtp",
        [15] = "heartbeat",
        [16] = "application_layer_protocol_negotiation",
        [17] = "status_request_v2",
        [18] = "signed_certificate_timestamp",
        [21] = "padding",
        [22] = "encrypt_then_mac",
        [23] = "extended_master_secret",
        [27] = "compress_certificate",
        [28] = "record_size_limit",
        [34] = "delegated_credentials",
        [35] = "session_ticket",
        [41] = "pre_shared_key",
        [42] = "early_data",
        [43] = "supported_versions",
        [44] = "cookie",
        [45] = "psk_key_exchange_modes",
        [49] = "post_handshake_auth",
        [50] = "signature_algorithms_cert",
        [51] = "key_share",
        [57] = "quic_transport_parameters",
        [17513] = "application_settings_old",
        [17613] = "application_settings",
        [0xFE0D] = "encrypted_client_hello",
        [0xFF01] = "renegotiation_info",
    }.ToFrozenDictionary();

    private static readonly FrozenDictionary<ushort, string> Groups = new Dictionary<ushort, string>
    {
        [23] = "secp256r1",
        [24] = "secp384r1",
        [25] = "secp521r1",
        [29] = "x25519",
        [30] = "x448",
        [256] = "ffdhe2048",
        [257] = "ffdhe3072",
        [258] = "ffdhe4096",
        [259] = "ffdhe6144",
        [260] = "ffdhe8192",
        [0x0200] = "MLKEM512",
        [0x0201] = "MLKEM768",
        [0x0202] = "MLKEM1024",
        [0x11EB] = "SecP256r1MLKEM768",
        [0x11EC] = "X25519MLKEM768",
        [0x11ED] = "SecP384r1MLKEM1024",
        [0x6399] = "X25519Kyber768Draft00",
    }.ToFrozenDictionary();

    private static readonly FrozenDictionary<ushort, string> SignatureSchemes = new Dictionary<ushort, string>
    {
        [0x0201] = "rsa_pkcs1_sha1",
        [0x0203] = "ecdsa_sha1",
        [0x0401] = "rsa_pkcs1_sha256",
        [0x0501] = "rsa_pkcs1_sha384",
        [0x0601] = "rsa_pkcs1_sha512",
        [0x0403] = "ecdsa_secp256r1_sha256",
        [0x0503] = "ecdsa_secp384r1_sha384",
        [0x0603] = "ecdsa_secp521r1_sha512",
        [0x0804] = "rsa_pss_rsae_sha256",
        [0x0805] = "rsa_pss_rsae_sha384",
        [0x0806] = "rsa_pss_rsae_sha512",
        [0x0807] = "ed25519",
        [0x0808] = "ed448",
        [0x0809] = "rsa_pss_pss_sha256",
        [0x080A] = "rsa_pss_pss_sha384",
        [0x080B] = "rsa_pss_pss_sha512",
        [0x0904] = "mldsa44",
        [0x0905] = "mldsa65",
        [0x0906] = "mldsa87",
    }.ToFrozenDictionary();

    public static bool IsGrease(ushort value) => (value & 0x0F0F) == 0x0A0A && value >> 8 == (value & 0xFF);

    public static string CipherSuite(ushort value) => Describe(value, CipherSuites);

    public static string Extension(ushort value) => IsGrease(value) ? "GREASE" : Extensions.GetValueOrDefault(value, "unknown");

    public static string Group(ushort value) => Describe(value, Groups);

    public static string SignatureScheme(ushort value) => Describe(value, SignatureSchemes);

    public static string Version(ushort value) => value switch
    {
        0x0304 => "0x0304 TLS 1.3",
        0x0303 => "0x0303 TLS 1.2",
        0x0302 => "0x0302 TLS 1.1",
        0x0301 => "0x0301 TLS 1.0",
        _ => Describe(value, FrozenDictionary<ushort, string>.Empty),
    };

    public static string CertificateCompression(ushort value) => value switch
    {
        1 => "zlib",
        2 => "brotli",
        3 => "zstd",
        _ => Hex(value),
    };

    public static string PskMode(byte value) => value switch
    {
        0 => "psk_ke",
        1 => "psk_dhe_ke",
        _ => Hex(value),
    };

    public static string HpkeKdf(ushort value) => value switch
    {
        1 => "HKDF-SHA256",
        2 => "HKDF-SHA384",
        3 => "HKDF-SHA512",
        _ => Hex(value),
    };

    public static string HpkeAead(ushort value) => value switch
    {
        1 => "AES-128-GCM",
        2 => "AES-256-GCM",
        3 => "ChaCha20Poly1305",
        _ => Hex(value),
    };

    public static string Hex(ushort value) => "0x" + value.ToString("x4", CultureInfo.InvariantCulture);

    private static string Describe(ushort value, FrozenDictionary<ushort, string> names) =>
        IsGrease(value) ? $"{Hex(value)} GREASE"
        : names.TryGetValue(value, out var name) ? $"{Hex(value)} {name}"
        : Hex(value);
}
