namespace Chameleon.Net.Tls;

/// <summary>ALPS (draft-vvv-tls-alps): the client's half of the exchange, sent encrypted after the server's Finished.</summary>
internal static class ApplicationSettings
{
    /// <summary>BoringSSL sends the client's settings in an EncryptedExtensions message (type 8), not the draft's separate type.</summary>
    private const byte EncryptedExtensionsType = 8;

    /// <summary>An EncryptedExtensions handshake message carrying one application_settings extension. The settings are empty:
    /// servers treat them as optional hints.</summary>
    public static byte[] ClientEncryptedExtensions(ushort codepoint)
    {
        byte[] extensions = [(byte)(codepoint >> 8), (byte)codepoint, 0, 0];
        byte[] body = [0, (byte)extensions.Length, .. extensions];
        return [EncryptedExtensionsType, 0, 0, (byte)body.Length, .. body];
    }
}
