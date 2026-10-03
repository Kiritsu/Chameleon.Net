using System.Security.Cryptography;
using System.Text;
using Chameleon.Net.Inspector.Reports;

namespace Chameleon.Net.Inspector.Analysis;

/// <summary>JA4H (FoxIO): <c>[method][version][cookie][referer][header count][accept-language]_[header names]_[cookie names]_[cookies]</c>.
/// Header names are hashed in the order received, without pseudo-headers, Cookie and Referer; cookies are sorted.</summary>
internal static class Ja4H
{
    private const string Empty = "000000000000";

    public static (string Hashed, string Raw) Compute(string method, string version, IReadOnlyList<HeaderField> headers)
    {
        var names = headers.Where(static h => !h.Name.StartsWith(':') && !IsCookie(h.Name) && !IsReferer(h.Name)).Select(static h => h.Name).ToList();
        var cookies = headers.Where(static h => IsCookie(h.Name))
            .SelectMany(static h => h.Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .ToList();
        var cookieNames = cookies.Select(static c => c.Split('=', 2)[0]).Order(StringComparer.Ordinal).ToList();
        var cookiePairs = cookies.Order(StringComparer.Ordinal).ToList();

        var prefix = string.Concat(
            method.Length >= 2 ? method[..2].ToLowerInvariant() : method.ToLowerInvariant().PadRight(2, '0'),
            version switch { "2" => "20", "3" => "30", "1.0" => "10", _ => "11" },
            cookies.Count > 0 ? "c" : "n",
            headers.Any(static h => IsReferer(h.Name)) ? "r" : "n",
            Math.Min(99, names.Count).ToString("D2", System.Globalization.CultureInfo.InvariantCulture),
            Language(headers.FirstOrDefault(static h => h.Name.Equals("accept-language", StringComparison.OrdinalIgnoreCase))?.Value));

        var headerList = string.Join(',', names);
        var cookieNameList = string.Join(',', cookieNames);
        var cookieList = string.Join(',', cookiePairs);
        var hashed = $"{prefix}_{Hash(headerList)}_{Hash(cookieNameList)}_{Hash(cookieList)}";
        var raw = $"{prefix}_{headerList}_{cookieNameList}_{cookieList}";
        return (hashed, raw);
    }

    private static string Language(string? acceptLanguage)
    {
        if (string.IsNullOrEmpty(acceptLanguage))
        {
            return "0000";
        }

        var first = acceptLanguage.Split(',', ';')[0].Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();
        return first.Length >= 4 ? first[..4] : first.PadRight(4, '0');
    }

    private static string Hash(string value) =>
        value.Length == 0 ? Empty : Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..12];

    private static bool IsCookie(string name) => name.Equals("cookie", StringComparison.OrdinalIgnoreCase);

    private static bool IsReferer(string name) => name.Equals("referer", StringComparison.OrdinalIgnoreCase);
}
