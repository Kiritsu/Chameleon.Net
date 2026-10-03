using System.Security.Cryptography;
using System.Text;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Inspector.Tls;

namespace Chameleon.Net.Inspector.Analysis;

internal sealed class ReportBuilder(KnownClients known)
{
    /// <summary>OkHttp's <c>ConnectionSpec.MODERN_TLS</c>: OkHttp sets the cipher list itself, so it's the same on every Android version.</summary>
    private static readonly ushort[] OkHttpCipherSuites = [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035];

    public KnownClients Known => known;

    /// <param name="request">Null when the connection ended before a request: the report then covers the TLS handshake only.</param>
    public InspectionReport Build(ConnectionCapture connection, RequestCapture? request, string? error = null)
    {
        var tls = connection.Hello is null || connection.Fingerprint is null ? null : TlsReport(connection);
        var http = request is null ? null : HttpReport(connection, request);
        var userAgent = UserAgentParser.Parse(request?.Header("user-agent"));

        IReadOnlyList<KnownClient> tlsMatches = connection.Hello is null ? [] : known.MatchTls(connection.Hello);
        var (tlsFamily, tlsReason) = connection.Hello is null ? (ClientFamily.Unknown, "plain HTTP: no TLS") : ClassifyTls(connection.Hello, tlsMatches);
        var http2 = request?.Version == "2" ? connection.Http2 : null;
        IReadOnlyList<KnownClient> http2Matches = http2 is null ? [] : known.MatchHttp2(http2.Akamai);
        ClientFamily? http2Family = http2 is null ? null : ClassifyHttp2(http2.Akamai, http2Matches);

        var client = new ClientReport(userAgent, tlsFamily, tlsReason, [.. tlsMatches.Select(static c => c.Name)], http2Family,
            [.. http2Matches.Select(static c => c.Name)]);
        var findings = request is null
            ? []
            : new ConsistencyChecker(known, connection, request, client, tlsMatches, http2Matches).Run();
        var verdict = findings.Count == 0 ? Verdict.Consistent : findings.Max(static f => f.Severity) switch
        {
            Severity.High => Verdict.Inconsistent,
            Severity.Medium => Verdict.Suspicious,
            _ => Verdict.Consistent,
        };

        var connectionReport = new ConnectionReport(connection.Id, request is null ? 0 : connection.NextRequest(), connection.Remote.ToString(),
            connection.Hello is not null, connection.TlsVersion, connection.CipherSuite, connection.Alpn, error);
        return new InspectionReport(connectionReport, tls, http, client, findings, verdict);
    }

    public static (ClientFamily Family, string Reason) ClassifyTls(ClientHelloDetails hello, IReadOnlyList<KnownClient> matches)
    {
        if (matches.Count > 0)
        {
            return (matches[0].Family, $"matches {string.Join(", ", matches.Select(static m => m.Name))}");
        }

        var grease = hello.CipherSuites.Any(TlsNames.IsGrease);
        if (grease && hello.AlpsCodepoint is not null)
        {
            return (ClientFamily.Chromium, "GREASE and ALPS: BoringSSL as Chrome configures it, but not a known version");
        }

        if (grease)
        {
            return (ClientFamily.Safari, "GREASE without ALPS: BoringSSL as Apple's network stack configures it");
        }

        if (hello.HasExtension(34) && hello.HasExtension(28))
        {
            return (ClientFamily.Firefox, "delegated_credentials and record_size_limit without GREASE: NSS, but not a known version");
        }

        if (hello.CipherSuites.SequenceEqual(OkHttpCipherSuites))
        {
            return (ClientFamily.OkHttp, "OkHttp's MODERN_TLS cipher list without GREASE, but not a known version");
        }

        var traits = new List<string> { "no GREASE" };
        if (hello.HasExtension(22))
        {
            traits.Add("encrypt_then_mac (OpenSSL's default; browsers don't send it)");
        }

        if (hello.CipherSuites is [0x1302, ..])
        {
            traits.Add("TLS_AES_256_GCM_SHA384 first (OpenSSL and SChannel order; browsers and OkHttp lead with AES-128)");
        }

        if (hello.AlpsCodepoint is null && hello.CertificateCompression.Count == 0)
        {
            traits.Add("no certificate compression");
        }

        return (ClientFamily.Unknown, $"matches no known client: {string.Join(", ", traits)}");
    }

    public static ClientFamily ClassifyHttp2(string akamai, IReadOnlyList<KnownClient> matches)
    {
        if (matches.Count > 0)
        {
            return matches[0].Family;
        }

        var parts = akamai.Split('|');
        var settings = parts[0].Split(';');
        var pseudo = parts[^1];
        return pseudo == "m,a,s,p" && settings.Contains("4:6291456") ? ClientFamily.Chromium
            : pseudo == "m,p,a,s" && settings.Contains("4:131072") ? ClientFamily.Firefox
            : pseudo == "m,p,a,s" && parts[0] == "4:16777216" ? ClientFamily.OkHttp
            : ClientFamily.Unknown;
    }

    private static TlsReport TlsReport(ConnectionCapture connection)
    {
        var hello = connection.Hello!;
        var fingerprint = connection.Fingerprint!;
        return new TlsReport(
            fingerprint.Ja3,
            fingerprint.Ja3Hash,
            fingerprint.Ja4,
            fingerprint.Ja4Raw,
            TlsNames.Version(connection.RecordVersion),
            TlsNames.Version(hello.LegacyVersion),
            connection.HelloLength,
            hello.SessionIdLength,
            hello.ServerName,
            hello.Alpn,
            [.. hello.CipherSuites.Select(TlsNames.CipherSuite)],
            [.. hello.Extensions.Select(static e => new ExtensionReport(e.Type, TlsNames.Extension(e.Type), e.Data.Length))],
            [.. hello.SupportedGroups.Select(TlsNames.Group)],
            [.. hello.KeyShares.Select(static k => $"{TlsNames.Group(k.Group)} ({k.Length} bytes)")],
            [.. hello.SignatureAlgorithms.Select(TlsNames.SignatureScheme)],
            [.. hello.SupportedVersions.Select(TlsNames.Version)],
            [.. hello.EcPointFormats.Select(static f => (int)f)],
            [.. hello.PskKeyExchangeModes.Select(TlsNames.PskMode)],
            [.. hello.CertificateCompression.Select(TlsNames.CertificateCompression)],
            hello.AlpsCodepoint is { } codepoint ? new AlpsReport(codepoint, hello.AlpsProtocols) : null,
            hello.Ech is { } ech ? new EchReport(TlsNames.HpkeKdf(ech.Kdf), TlsNames.HpkeAead(ech.Aead), ech.ConfigId, ech.EncLength, ech.PayloadLength) : null,
            hello.RecordSizeLimit,
            [.. hello.DelegatedCredentials.Select(TlsNames.SignatureScheme)],
            hello.PaddingLength,
            hello.PreSharedKey is { } psk ? new PskReport(psk.IdentityLengths, psk.Binders) : null,
            hello.EarlyData,
            new GreaseReport(
                hello.CipherSuites.Any(TlsNames.IsGrease),
                [.. hello.Extensions.Select(static (e, i) => (e.Type, i)).Where(static e => TlsNames.IsGrease(e.Type)).Select(static e => e.i)],
                hello.SupportedGroups.Any(TlsNames.IsGrease),
                hello.KeyShares.Any(static k => TlsNames.IsGrease(k.Group)),
                hello.SupportedVersions.Any(TlsNames.IsGrease),
                hello.SignatureAlgorithms.Any(TlsNames.IsGrease)),
            connection.ExtensionOrder ?? new ExtensionOrderReport(1, 1));
    }

    private static HttpReport HttpReport(ConnectionCapture connection, RequestCapture request)
    {
        var (ja4h, ja4hRaw) = Ja4H.Compute(request.Method, request.Version, request.Headers);
        Http2Report? http2 = null;
        if (request.Version == "2" && connection.Http2 is { } capture)
        {
#pragma warning disable CA5351 // MD5 is what tls.peet.ws shows as the Akamai fingerprint hash, not a security use.
            var hash = Convert.ToHexStringLower(MD5.HashData(Encoding.ASCII.GetBytes(capture.Akamai)));
#pragma warning restore CA5351
            http2 = new Http2Report(capture.Akamai, hash, capture.Frames, capture.FirstStreamId, request.StreamId, request.Priority,
                string.Join(',', request.PseudoHeaders.Select(PseudoHeaderLetter)));
        }

        return new HttpReport(request.Version, request.Method, request.Path, request.Authority, request.Headers, ja4h, ja4hRaw, request.WebSocket, http2);
    }

    public static string PseudoHeaderLetter(string name) => name switch
    {
        ":method" => "m",
        ":authority" => "a",
        ":scheme" => "s",
        ":path" => "p",
        _ => name,
    };
}
