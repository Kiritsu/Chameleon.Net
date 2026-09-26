using System.Globalization;

namespace Chameleon.Net.Http;

internal static class HttpUris
{
    /// <summary>Host to resolve and to send as SNI: punycode, IPv6 without brackets.</summary>
    public static string ConnectHost(Uri uri) => uri.HostNameType == UriHostNameType.IPv6 ? uri.DnsSafeHost : uri.IdnHost;

    public static int Port(Uri uri) => uri.IsDefaultPort ? DefaultPort(uri.Scheme) : uri.Port;

    /// <summary><c>Host</c> header value: port only when not the scheme's default.</summary>
    public static string Authority(Uri uri)
    {
        var host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host : uri.IdnHost;
        return uri.IsDefaultPort ? host : string.Create(CultureInfo.InvariantCulture, $"{host}:{uri.Port}");
    }

    public static bool IsSecure(string scheme) => scheme is "https" or "wss";

    private static int DefaultPort(string scheme) => IsSecure(scheme) ? 443 : 80;
}
