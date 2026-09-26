using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace Chameleon.Net.Tls;

/// <summary>Post-quantum hybrid key exchange (draft-ietf-tls-ecdhe-mlkem), composed from BouncyCastle's own ML-KEM and ECDH agreements,
/// which BouncyCastle 2.6 does not offer as TLS groups. Shares and secrets are the two components concatenated in the order the codepoint defines.</summary>
internal sealed class HybridKeyAgreement : TlsAgreement
{
    public const int X25519MLKEM768 = 0x11EC;
    public const int SecP256r1MLKEM768 = 0x11EB;
    public const int SecP384r1MLKEM1024 = 0x11ED;

    private readonly TlsAgreement _first;
    private readonly TlsAgreement _second;
    private readonly int _firstServerShareLength;
    private readonly TlsCrypto _crypto;

    private HybridKeyAgreement(TlsCrypto crypto, TlsAgreement first, int firstServerShareLength, TlsAgreement second)
    {
        _crypto = crypto;
        _first = first;
        _firstServerShareLength = firstServerShareLength;
        _second = second;
    }

    public static bool IsHybrid(int group) => group is X25519MLKEM768 or SecP256r1MLKEM768 or SecP384r1MLKEM1024;

    public static HybridKeyAgreement Create(TlsCrypto crypto, int group) => group switch
    {
        // ML-KEM first for X25519MLKEM768; ECDH first for the NIST-curve hybrids.
        X25519MLKEM768 => new(crypto, Kem(crypto, NamedGroup.MLKEM768), 1088, Ecdh(crypto, NamedGroup.x25519)),
        SecP256r1MLKEM768 => new(crypto, Ecdh(crypto, NamedGroup.secp256r1), 65, Kem(crypto, NamedGroup.MLKEM768)),
        SecP384r1MLKEM1024 => new(crypto, Ecdh(crypto, NamedGroup.secp384r1), 97, Kem(crypto, NamedGroup.MLKEM1024)),
        _ => throw new ArgumentOutOfRangeException(nameof(group), group, "Not a supported hybrid group."),
    };

    public byte[] GenerateEphemeral() => [.. _first.GenerateEphemeral(), .. _second.GenerateEphemeral()];

    public void ReceivePeerValue(byte[] peerValue)
    {
        ArgumentNullException.ThrowIfNull(peerValue);
        if (peerValue.Length <= _firstServerShareLength)
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        _first.ReceivePeerValue(peerValue[.._firstServerShareLength]);
        _second.ReceivePeerValue(peerValue[_firstServerShareLength..]);
    }

    public TlsSecret CalculateSecret() =>
        _crypto.CreateSecret([.. _first.CalculateSecret().Extract(), .. _second.CalculateSecret().Extract()]);

    private static TlsAgreement Kem(TlsCrypto crypto, int group) => crypto.CreateKemDomain(new TlsKemConfig(group, isServer: false)).CreateKem();

    private static TlsAgreement Ecdh(TlsCrypto crypto, int group) => crypto.CreateECDomain(new TlsECConfig(group)).CreateECDH();
}
