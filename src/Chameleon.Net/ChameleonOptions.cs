using System.Net;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Microsoft.Extensions.Logging;

namespace Chameleon.Net;

/// <summary>Read once, when the handler is constructed.</summary>
public sealed class ChameleonOptions
{
    /// <summary>Picks the profile for each new connection. Required unless the handler is given a single profile.</summary>
    public IProfileSelector? ProfileSelector { get; set; }

    /// <summary>HTTP proxies tunnel https and wss with CONNECT and receive plain http and ws requests in absolute form, as OkHttp does; SOCKS5 proxies natively
    /// (<c>socks5://user:pass@host:1080</c>). Credentials come from the proxy URI or <see cref="IWebProxy.Credentials"/> and are sent preemptively.
    /// The TLS and HTTP fingerprints seen by the target are unchanged.</summary>
    public IWebProxy? Proxy { get; set; }

    /// <summary>TCP connect plus TLS handshake.</summary>
    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public bool AllowAutoRedirect { get; set; } = true;

    public int MaxAutomaticRedirections { get; set; } = 20;

    /// <summary>Null (the default) means no cookie handling, like OkHttp without a CookieJar.</summary>
    public CookieContainer? Cookies { get; set; }

    /// <summary>Defaults to <see cref="SystemCertificateValidator"/>.</summary>
    public IServerCertificateValidator? CertificateValidator { get; set; }

    /// <summary>Not supported yet; setting it throws.</summary>
    public ITcpFingerprintApplicator? TcpFingerprintApplicator { get; set; }

    public ILoggerFactory? LoggerFactory { get; set; }

    /// <summary>Resume TLS 1.3 sessions with tickets from earlier connections to the same host, as Chrome and OkHttp (Conscrypt) do.
    /// Applies to profiles that list psk_key_exchange_modes. On by default; turn off to make every connection a full handshake.</summary>
    public bool TlsSessionResumption { get; set; } = true;

    /// <summary>Null (the default): each handler or connector keeps its own tickets. Give the handler and the WebSocket connector the same
    /// instance to have them resume each other's sessions, like one OkHttpClient used for both.</summary>
    public TlsSessionCache? TlsSessionCache { get; set; }
}
