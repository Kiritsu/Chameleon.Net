using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace Chameleon.Net.Tls;

/// <summary>The RFC 8446 key-schedule steps BouncyCastle 2.6 lacks for session resumption, built from its public HKDF primitives.</summary>
internal static class Tls13Resumption
{
    /// <summary>resumption_master_secret = Derive-Secret(master_secret, "res master", ClientHello..client Finished).</summary>
    public static TlsSecret ResumptionMasterSecret(TlsSecret masterSecret, int cryptoHashAlgorithm, byte[] transcriptHashThroughClientFinished) =>
        TlsCryptoUtilities.HkdfExpandLabel(masterSecret, cryptoHashAlgorithm, "res master", transcriptHashThroughClientFinished,
            TlsCryptoUtilities.GetHashOutputSize(cryptoHashAlgorithm));

    /// <summary>PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length).</summary>
    public static byte[] TicketPsk(TlsSecret resumptionMasterSecret, int cryptoHashAlgorithm, byte[] nonce) =>
        TlsCryptoUtilities.HkdfExpandLabel(resumptionMasterSecret, cryptoHashAlgorithm, "resumption", nonce,
            TlsCryptoUtilities.GetHashOutputSize(cryptoHashAlgorithm)).Extract();

    /// <summary>PSK binder for a resumption PSK: HMAC(finished_key, Transcript-Hash(truncated ClientHello)), with
    /// finished_key derived from Derive-Secret(early_secret, "res binder", "").</summary>
    public static byte[] Binder(TlsCrypto crypto, byte[] psk, int cryptoHashAlgorithm, byte[] truncatedHelloTranscriptHash)
    {
        var hashLength = TlsCryptoUtilities.GetHashOutputSize(cryptoHashAlgorithm);
        var earlySecret = crypto.HkdfInit(cryptoHashAlgorithm).HkdfExtract(cryptoHashAlgorithm, crypto.CreateSecret(psk));
        var emptyHash = crypto.CreateHash(cryptoHashAlgorithm).CalculateHash();
        var binderKey = TlsCryptoUtilities.HkdfExpandLabel(earlySecret, cryptoHashAlgorithm, "res binder", emptyHash, hashLength);
        var finishedKey = TlsCryptoUtilities.HkdfExpandLabel(binderKey, cryptoHashAlgorithm, "finished", TlsUtilities.EmptyBytes, hashLength);

        var hmac = crypto.CreateHmacForHash(cryptoHashAlgorithm);
        var key = finishedKey.Extract();
        hmac.SetKey(key, 0, key.Length);
        hmac.Update(truncatedHelloTranscriptHash, 0, truncatedHelloTranscriptHash.Length);
        return hmac.CalculateMac();
    }

    /// <summary>pre_shared_key ClientHello body with one identity and a zeroed binder of the right length (patched after encoding).</summary>
    public static byte[] PreSharedKeyBody(SessionTicket ticket)
    {
        var identity = ticket.Identity;
        var age = ticket.ObfuscatedAge;
        var identitiesLength = 2 + identity.Length + 4;
        var hashLength = ticket.HashLength;

        byte[] body =
        [
            (byte)(identitiesLength >> 8), (byte)identitiesLength,
            (byte)(identity.Length >> 8), (byte)identity.Length, .. identity,
            (byte)(age >> 24), (byte)(age >> 16), (byte)(age >> 8), (byte)age,
            (byte)((hashLength + 1) >> 8), (byte)(hashLength + 1),
            (byte)hashLength, .. new byte[hashLength],
        ];
        return body;
    }
}
