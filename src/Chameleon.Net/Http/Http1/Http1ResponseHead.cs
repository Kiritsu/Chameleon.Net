using System.Globalization;
using System.Text;

namespace Chameleon.Net.Http.Http1;

internal sealed record Http1ResponseHead(Version Version, int StatusCode, string ReasonPhrase, IReadOnlyList<KeyValuePair<string, string>> Headers)
{
    public IEnumerable<string> GetValues(string name) =>
        Headers.Where(header => string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase)).Select(static header => header.Value);

    public string? GetValue(string name) => GetValues(name).FirstOrDefault();

    /// <summary>True when any comma-separated element of any <paramref name="name"/> header equals <paramref name="token"/>, ignoring case.</summary>
    public bool HasToken(string name, string token) =>
        GetValues(name).Any(value => value.Split(',', StringSplitOptions.TrimEntries)
            .Any(element => string.Equals(element, token, StringComparison.OrdinalIgnoreCase)));

    /// <summary>Parses the head without its terminating empty line.</summary>
    /// <exception cref="HttpIOException">The status line or a header line is malformed.</exception>
    public static Http1ResponseHead Parse(ReadOnlySpan<byte> head)
    {
        var lines = Encoding.Latin1.GetString(head).Split("\r\n");
        var statusLine = lines[0];

        // HTTP/1.x SP 3DIGIT [SP reason]
        if (statusLine.Length < 12
            || !statusLine.StartsWith("HTTP/1.", StringComparison.Ordinal)
            || !char.IsAsciiDigit(statusLine[7])
            || statusLine[8] != ' '
            || !int.TryParse(statusLine.AsSpan(9, 3), NumberStyles.None, CultureInfo.InvariantCulture, out var statusCode)
            || (statusLine.Length > 12 && statusLine[12] != ' '))
        {
            throw Invalid($"Malformed status line '{statusLine}'.");
        }

        var headers = new List<KeyValuePair<string, string>>(lines.Length - 1);
        foreach (var line in lines.AsSpan(1))
        {
            var colon = line.IndexOf(':', StringComparison.Ordinal);
            if (colon <= 0 || line[0] is ' ' or '\t' || char.IsWhiteSpace(line[colon - 1]))
            {
                throw Invalid($"Malformed header line '{line}'.");
            }

            headers.Add(new(line[..colon], line[(colon + 1)..].Trim(' ', '\t')));
        }

        return new Http1ResponseHead(
            new Version(1, statusLine[7] - '0'),
            statusCode,
            statusLine.Length > 13 ? statusLine[13..] : string.Empty,
            headers);
    }

    private static HttpIOException Invalid(string message) => new(HttpRequestError.InvalidResponse, message);
}
