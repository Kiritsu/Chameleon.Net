using Chameleon.Net.Inspector.Reports;

namespace Chameleon.Net.Inspector;

/// <summary>One block per report on the console; the full report is in the HTTP response and the JSON log.</summary>
internal static class ReportPrinter
{
    public static void Print(InspectionReport report, TextWriter writer)
    {
        var connection = report.Connection;
        var http = report.Http;
        writer.WriteLine();
        writer.WriteLine(http is null
            ? $"#{connection.Id} {connection.Remote}  TLS only: {connection.Error}"
            : $"#{connection.Id}.{connection.Request} {connection.Remote}  {(connection.Tls ? "https" : "http")} HTTP/{http.Version}  {http.Method} {http.Path}{(http.WebSocket ? "  (WebSocket)" : "")}");

        if (report.Client.UserAgent is { } userAgent)
        {
            Line(writer, "User-Agent", $"{userAgent.Product} {userAgent.MajorVersion}{(userAgent.Platform is null ? "" : $" on {userAgent.Platform}")} ({userAgent.Family})");
        }

        if (report.Tls is { } tls)
        {
            Line(writer, "JA4", $"{tls.Ja4}  {Matches(report.Client.TlsMatches)}");
            Line(writer, "JA3", tls.Ja3Hash);
            Line(writer, "TLS stack", $"{report.Client.TlsFamily}: {report.Client.TlsFamilyReason}");
        }

        if (http?.Http2 is { } http2)
        {
            Line(writer, "Akamai", $"{http2.Akamai}  {Matches(report.Client.Http2Matches)}");
        }

        if (http is not null)
        {
            Line(writer, "JA4H", http.Ja4H);
            Line(writer, "Headers", string.Join(", ", http.Headers.Select(static h => h.Name)));
        }

        Line(writer, "Verdict", report.Verdict.ToString());
        foreach (var finding in report.Findings)
        {
            writer.WriteLine($"  {Mark(finding.Severity)} {finding.Id}: {finding.Message}");
        }
    }

    private static string Matches(IReadOnlyList<string> matches) => matches.Count == 0 ? "(no built-in profile)" : $"= {string.Join(", ", matches)}";

    private static string Mark(Severity severity) => severity switch
    {
        Severity.High => "[high]  ",
        Severity.Medium => "[medium]",
        Severity.Low => "[low]   ",
        _ => "[info]  ",
    };

    private static void Line(TextWriter writer, string label, string value) => writer.WriteLine($"  {label,-11} {value}");
}
