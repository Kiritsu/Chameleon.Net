using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Chameleon.Net.Tls;

/// <summary>Chain building through the OS trust store plus subjectAltName host matching, as SslStream would do.</summary>
public sealed class SystemCertificateValidator : IServerCertificateValidator
{
    public X509RevocationMode RevocationMode { get; init; } = X509RevocationMode.NoCheck;

    public void Validate(X509Certificate2Collection chain, string targetHost)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentException.ThrowIfNullOrEmpty(targetHost);

        if (chain.Count == 0)
        {
            throw new AuthenticationException("The server sent no certificate.");
        }

        var leaf = chain[0];
        using var builder = new X509Chain();
        builder.ChainPolicy.RevocationMode = RevocationMode;
        for (var i = 1; i < chain.Count; i++)
        {
            builder.ChainPolicy.ExtraStore.Add(chain[i]);
        }

        if (!builder.Build(leaf))
        {
            var reasons = string.Join("; ", builder.ChainStatus.Select(static status => status.StatusInformation.Trim()));
            throw new AuthenticationException($"Certificate chain validation failed for '{targetHost}': {reasons}");
        }

        if (!MatchesHost(leaf, targetHost))
        {
            throw new AuthenticationException($"Certificate does not match host '{targetHost}'.");
        }
    }

    private static bool MatchesHost(X509Certificate2 leaf, string targetHost)
    {
        var alternativeNames = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (alternativeNames is null)
        {
            return false;
        }

        if (IPAddress.TryParse(targetHost, out var address))
        {
            return alternativeNames.EnumerateIPAddresses().Any(candidate => candidate.Equals(address));
        }

        var host = targetHost.TrimEnd('.');
        return alternativeNames.EnumerateDnsNames().Any(pattern => MatchesDnsName(pattern.TrimEnd('.'), host));
    }

    private static bool MatchesDnsName(string pattern, string host)
    {
        if (!pattern.StartsWith("*.", StringComparison.Ordinal))
        {
            return string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase);
        }

        var firstLabelEnd = host.IndexOf('.', StringComparison.Ordinal);
        return firstLabelEnd > 0
            && pattern.AsSpan(2).Equals(host.AsSpan(firstLabelEnd + 1), StringComparison.OrdinalIgnoreCase);
    }
}
