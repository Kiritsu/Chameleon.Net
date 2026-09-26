namespace Chameleon.Net.Profiles;

internal static class TlsProfileExtensions
{
    /// <summary>Same ClientHello, different ALPN offer. Profiles without an ALPN extension are returned unchanged.</summary>
    public static TlsProfile WithAlpn(this TlsProfile tls, IReadOnlyList<string> protocols) => tls with
    {
        Extensions = [.. tls.Extensions.Select(extension => extension is AlpnExtension ? new AlpnExtension(protocols) : extension)],
        SessionScope = tls.SessionScope ?? tls,
    };
}
