using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Chameleon.Net.Tls;

namespace Chameleon.Net.Tests.Support;

internal static class TestCertificates
{
    /// <summary>ECDSA P-256 for 127.0.0.1, usable by Kestrel (SChannel can't use an ephemeral key, hence the PFX round trip).</summary>
    public static X509Certificate2 SelfSigned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=127.0.0.1", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(System.Net.IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null);
    }
}

internal sealed class TrustAnyCertificate : IServerCertificateValidator
{
    public void Validate(X509Certificate2Collection chain, string targetHost)
    {
    }
}
