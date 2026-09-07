using System.Net;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Microsoft.Extensions.Logging;

namespace Chameleon.Net;

public sealed class ChameleonOptions
{
    public IProfileSelector? ProfileSelector { get; set; }

    public IWebProxy? Proxy { get; set; }

    public TimeSpan ConnectTimeout { get; set; } = TimeSpan.FromSeconds(30);

    public bool AllowAutoRedirect { get; set; } = true;

    public int MaxAutomaticRedirections { get; set; } = 20;

    public CookieContainer? Cookies { get; set; }

    public IServerCertificateValidator? CertificateValidator { get; set; }

    public ITcpFingerprintApplicator? TcpFingerprintApplicator { get; set; }

    public ILoggerFactory? LoggerFactory { get; set; }
}
