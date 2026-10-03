namespace Chameleon.Net.Profiles;

internal static class TlsProfileExtensions
{
    /// <summary>Same ClientHello, different ALPN offer. Profiles without an ALPN extension are returned unchanged.
    /// ALPS follows the offer, as in BoringSSL: it's sent only for offered protocols, so Chrome's WebSocket connections
    /// (ALPN <c>http/1.1</c> alone) carry no ALPS.</summary>
    public static TlsProfile WithAlpn(this TlsProfile tls, IReadOnlyList<string> protocols) => tls with
    {
        Extensions =
        [
            .. tls.Extensions
                .Select(extension => extension switch
                {
                    AlpnExtension => new AlpnExtension(protocols),
                    ApplicationSettingsExtension alps => alps.Protocols.Any(protocols.Contains)
                        ? alps with { Protocols = [.. alps.Protocols.Where(protocols.Contains)] }
                        : null,
                    _ => extension,
                })
                .OfType<TlsExtension>(),
        ],
        SessionScope = tls.SessionScope ?? tls,
    };
}
