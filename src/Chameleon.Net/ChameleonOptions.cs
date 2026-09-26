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

    /// <summary>Not supported yet; setting it throws.</summary>
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
}
