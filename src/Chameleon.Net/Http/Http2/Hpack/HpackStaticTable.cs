namespace Chameleon.Net.Http.Http2.Hpack;

/// <summary>RFC 7541 Appendix A. HPACK indices are 1-based: entry <c>i</c> is <c>Entries[i - 1]</c>.</summary>
internal static class HpackStaticTable
{
    public static readonly KeyValuePair<string, string>[] Entries =
    [
        new(":authority", ""),
        new(":method", "GET"),
        new(":method", "POST"),
        new(":path", "/"),
        new(":path", "/index.html"),
        new(":scheme", "http"),
        new(":scheme", "https"),
        new(":status", "200"),
        new(":status", "204"),
        new(":status", "206"),
        new(":status", "304"),
        new(":status", "400"),
        new(":status", "404"),
        new(":status", "500"),
        new("accept-charset", ""),
        new("accept-encoding", "gzip, deflate"),
        new("accept-language", ""),
        new("accept-ranges", ""),
        new("accept", ""),
        new("access-control-allow-origin", ""),
        new("age", ""),
        new("allow", ""),
        new("authorization", ""),
        new("cache-control", ""),
        new("content-disposition", ""),
        new("content-encoding", ""),
        new("content-language", ""),
        new("content-length", ""),
        new("content-location", ""),
        new("content-range", ""),
        new("content-type", ""),
        new("cookie", ""),
        new("date", ""),
        new("etag", ""),
        new("expect", ""),
        new("expires", ""),
        new("from", ""),
        new("host", ""),
        new("if-match", ""),
        new("if-modified-since", ""),
        new("if-none-match", ""),
        new("if-range", ""),
        new("if-unmodified-since", ""),
        new("last-modified", ""),
        new("link", ""),
        new("location", ""),
        new("max-forwards", ""),
        new("proxy-authenticate", ""),
        new("proxy-authorization", ""),
        new("range", ""),
        new("referer", ""),
        new("refresh", ""),
        new("retry-after", ""),
        new("server", ""),
        new("set-cookie", ""),
        new("strict-transport-security", ""),
        new("transfer-encoding", ""),
        new("user-agent", ""),
        new("vary", ""),
        new("via", ""),
        new("www-authenticate", ""),
    ];

    public static int Count => Entries.Length;

    /// <returns>The first 1-based index whose name matches, or 0.</returns>
    public static int IndexOfName(string name)
    {
        for (var i = 0; i < Entries.Length; i++)
        {
            if (string.Equals(Entries[i].Key, name, StringComparison.Ordinal))
            {
                return i + 1;
            }
        }

        return 0;
    }
}
