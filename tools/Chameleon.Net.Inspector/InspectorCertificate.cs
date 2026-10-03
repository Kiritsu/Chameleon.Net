using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Chameleon.Net.Inspector;

internal static class InspectorCertificate
{
    /// <summary>ECDSA P-256 for localhost, this machine's name and addresses. Clients have to skip validation or trust it; a client that
    /// rejects it still gets its ClientHello reported.</summary>
    public static X509Certificate2 CreateSelfSigned()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Chameleon.Net Inspector", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName("localhost");
        names.AddDnsName(Environment.MachineName);
        names.AddIpAddress(IPAddress.Loopback);
        names.AddIpAddress(IPAddress.IPv6Loopback);
        foreach (var address in LocalAddresses())
        {
            names.AddIpAddress(address);
        }

        request.CertificateExtensions.Add(names.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false));
        using var ephemeral = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        // SChannel can't use an ephemeral key: round-trip through PFX.
        return X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null);
    }

    public static X509Certificate2 Load(string path, string? password) => X509CertificateLoader.LoadPkcs12FromFile(path, password);

    private static List<IPAddress> LocalAddresses()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(static n => n.OperationalStatus == OperationalStatus.Up)
                .SelectMany(static n => n.GetIPProperties().UnicastAddresses)
                .Select(static a => a.Address)
                .Where(static a => a.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(a))
                .Distinct()
                .ToList();
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }
}
