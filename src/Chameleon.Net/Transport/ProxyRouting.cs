using System.Net;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Transport;

/// <summary>Maps each target to a transport from an <see cref="IWebProxy"/>: direct, an HTTP CONNECT tunnel, or SOCKS5.
/// Plain-http targets behind an HTTP proxy are not tunnelled: like OkHttp, the client talks to the proxy and sends absolute-form requests
/// (see <see cref="ForwardProxyFor"/>).</summary>
internal sealed class ProxyRouting(ITransport direct, IWebProxy? proxy)
{
    public ITransport For(Uri target, ClientProfile profile)
    {
        if (proxy is null || proxy.IsBypassed(target) || proxy.GetProxy(target) is not { } proxyUri || proxyUri == target)
        {
            return direct;
        }

        var endpoint = new DnsEndPoint(proxyUri.IdnHost, proxyUri.Port);
        var credentials = Credentials(proxyUri);
        return proxyUri.Scheme.ToLowerInvariant() switch
        {
            "http" => new HttpConnectTransport(direct, endpoint, credentials,
                profile.Headers.DefaultHeaders.FirstOrDefault(static h => string.Equals(h.Key, "User-Agent", StringComparison.OrdinalIgnoreCase)).Value),
            "socks5" or "socks5h" => new Socks5Transport(direct, endpoint, credentials),
            _ => throw new NotSupportedException($"Proxy scheme '{proxyUri.Scheme}' is not supported; use http or socks5."),
        };
    }

    /// <summary>For an <c>http://</c> target behind an HTTP proxy: where to connect and the preemptive Proxy-Authorization, if any.
    /// Null when the request should go direct or through a tunnel.</summary>
    public ForwardProxy? ForwardProxyFor(Uri target)
    {
        if (!string.Equals(target.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
            || proxy is null || proxy.IsBypassed(target) || proxy.GetProxy(target) is not { } proxyUri || proxyUri == target
            || !string.Equals(proxyUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var credentials = Credentials(proxyUri);
        var authorization = credentials is null
            ? null
            : "Basic " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{credentials.UserName}:{credentials.Password}"));
        return new ForwardProxy(direct, new DnsEndPoint(proxyUri.IdnHost, proxyUri.Port), authorization);
    }

    public static void Validate(IWebProxy? proxy)
    {
        if (proxy is WebProxy { Address: { } address } && address.Scheme.ToLowerInvariant() is not ("http" or "socks5" or "socks5h"))
        {
            throw new NotSupportedException($"Proxy scheme '{address.Scheme}' is not supported; use http or socks5.");
        }
    }

    private NetworkCredential? Credentials(Uri proxyUri)
    {
        if (!string.IsNullOrEmpty(proxyUri.UserInfo))
        {
            var parts = proxyUri.UserInfo.Split(':', 2);
            return new NetworkCredential(Uri.UnescapeDataString(parts[0]), parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : string.Empty);
        }

        return proxy!.Credentials?.GetCredential(proxyUri, "Basic");
    }
}

/// <summary>An HTTP proxy that receives absolute-form requests directly (no CONNECT).</summary>
internal sealed record ForwardProxy(ITransport Transport, DnsEndPoint Endpoint, string? Authorization);
