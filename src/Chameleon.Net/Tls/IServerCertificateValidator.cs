using System.Security.Cryptography.X509Certificates;

namespace Chameleon.Net.Tls;

/// <summary>BouncyCastle hands over the raw chain and validates nothing; this is where trust is decided.</summary>
public interface IServerCertificateValidator
{
    void Validate(X509Certificate2Collection chain, string targetHost);
}
