using System.Globalization;
using System.Text.RegularExpressions;
using Chameleon.Net.Inspector.Reports;

namespace Chameleon.Net.Inspector.Analysis;

/// <summary>Just enough User-Agent parsing to know which stack a client claims to be: product, major version, platform.</summary>
internal static partial class UserAgentParser
{
    public static UserAgentReport? Parse(string? userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
        {
            return null;
        }

        var (product, family, version) = Product(userAgent);
        return new UserAgentReport(userAgent, product, family, version, Platform(userAgent), userAgent.Contains("Mobile", StringComparison.Ordinal));
    }

    private static (string Product, ClientFamily Family, int? Version) Product(string ua)
    {
        // iOS browsers all run on WebKit's network stack, whatever their name.
        if (ua.Contains("iPhone", StringComparison.Ordinal) || ua.Contains("iPad", StringComparison.Ordinal))
        {
            return Match(ua, "CriOS") is { } crios ? ("Chrome (iOS)", ClientFamily.Safari, crios)
                : Match(ua, "FxiOS") is { } fxios ? ("Firefox (iOS)", ClientFamily.Safari, fxios)
                : Match(ua, "EdgiOS") is { } edgios ? ("Edge (iOS)", ClientFamily.Safari, edgios)
                : ("Safari", ClientFamily.Safari, Match(ua, "Version"));
        }

        if (Match(ua, "okhttp") is { } okhttp)
        {
            return ("OkHttp", ClientFamily.OkHttp, okhttp);
        }

        if (Match(ua, "Firefox") is { } firefox)
        {
            return ("Firefox", ClientFamily.Firefox, firefox);
        }

        if (Match(ua, "Edg") is { } edge)
        {
            return ("Edge", ClientFamily.Chromium, edge);
        }

        if (Match(ua, "OPR") is { } opera)
        {
            return ("Opera", ClientFamily.Chromium, opera);
        }

        if (Match(ua, "Chrome") is { } chrome)
        {
            return ("Chrome", ClientFamily.Chromium, chrome);
        }

        if (ua.Contains("Safari/", StringComparison.Ordinal) && Match(ua, "Version") is { } safari)
        {
            return ("Safari", ClientFamily.Safari, safari);
        }

        foreach (var tool in (string[])["curl", "Wget", "python-requests", "python-httpx", "aiohttp", "Go-http-client", "axios", "node-fetch", "undici", "Java", "Apache-HttpClient", "PostmanRuntime", "Dart"])
        {
            if (ua.StartsWith(tool, StringComparison.OrdinalIgnoreCase))
            {
                return (tool, ClientFamily.Tool, Match(ua, tool));
            }
        }

        return (ua.Split('/', ' ')[0], ClientFamily.Unknown, null);
    }

    private static string? Platform(string ua) =>
        ua.Contains("iPhone", StringComparison.Ordinal) || ua.Contains("iPad", StringComparison.Ordinal) ? "iOS"
        : ua.Contains("Android", StringComparison.Ordinal) ? "Android"
        : ua.Contains("Windows", StringComparison.Ordinal) ? "Windows"
        : ua.Contains("CrOS", StringComparison.Ordinal) ? "Chrome OS"
        : ua.Contains("Macintosh", StringComparison.Ordinal) ? "macOS"
        : ua.Contains("Linux", StringComparison.Ordinal) ? "Linux"
        : null;

    private static int? Match(string ua, string product)
    {
        var match = VersionPattern().Match(ua, 0);
        while (match.Success)
        {
            if (string.Equals(match.Groups[1].Value, product, StringComparison.OrdinalIgnoreCase))
            {
                return int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
            }

            match = match.NextMatch();
        }

        return null;
    }

    [GeneratedRegex(@"([A-Za-z][A-Za-z\-_]*)/(\d{1,6})")]
    private static partial Regex VersionPattern();
}
