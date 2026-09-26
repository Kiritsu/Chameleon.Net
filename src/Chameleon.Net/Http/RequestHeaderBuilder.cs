using System.Collections.Frozen;
using System.Globalization;
using System.Net.Http.Headers;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Http;

/// <param name="Headers">In profile order and HTTP/1.1 casing; HTTP/2 lowercases and drops connection-specific fields.</param>
internal sealed record RequestHeaderPlan(
    IReadOnlyList<KeyValuePair<string, string>> Headers,
    long? ContentLength,
    bool Chunked,
    bool TransparentDecompression,
    bool CloseRequested);

/// <summary>Assembles the headers the client would send, the way OkHttp's BridgeInterceptor does: the caller's headers,
/// then framing, Host, cookies and the profile's defaults, finally ordered by the profile.</summary>
internal static class RequestHeaderBuilder
{
    /// <summary>Framing and Host are derived from the request; values the caller sets for them are ignored.</summary>
    private static readonly FrozenSet<string> Derived =
        FrozenSet.Create(StringComparer.OrdinalIgnoreCase, "Host", "Content-Length", "Transfer-Encoding");

    public static RequestHeaderPlan Build(HttpRequestMessage request, ClientProfile profile, RequestKind kind, string? cookieHeader)
    {
        var uri = request.RequestUri!;
        var headers = new List<KeyValuePair<string, string>>();

        AddCallerHeaders(headers, request.Headers);

        long? contentLength = null;
        var chunked = false;
        if (request.Content is { } content)
        {
            AddCallerHeaders(headers, content.Headers);
            contentLength = content.Headers.ContentLength;
            chunked = contentLength is null;
        }
        else if (request.Method == HttpMethod.Post || request.Method == HttpMethod.Put || request.Method == HttpMethod.Patch)
        {
            contentLength = 0;
        }

        if (contentLength is { } length)
        {
            headers.Add(new("Content-Length", length.ToString(CultureInfo.InvariantCulture)));
        }

        if (chunked)
        {
            headers.Add(new("Transfer-Encoding", "chunked"));
        }

        headers.Add(new("Host", Authority(request)));

        if (!string.IsNullOrEmpty(cookieHeader) && !Contains(headers, "Cookie"))
        {
            headers.Add(new("Cookie", cookieHeader));
        }

        // Like OkHttp, only decode bodies transparently when the Accept-Encoding came from the client, not the caller.
        var transparentDecompression = false;
        foreach (var (name, value) in profile.Headers.DefaultHeaders)
        {
            if (Contains(headers, name))
            {
                continue;
            }

            headers.Add(new(name, value));
            transparentDecompression |= string.Equals(name, "Accept-Encoding", StringComparison.OrdinalIgnoreCase);
        }

        var order = profile.Headers.Overrides.TryGetValue(kind, out var kindOrder) ? kindOrder : profile.Headers.HeaderOrder;
        return new RequestHeaderPlan(
            HeaderOrdering.Order(headers, order, profile.Headers.Http1Casing),
            contentLength,
            chunked,
            transparentDecompression,
            request.Headers.ConnectionClose == true);
    }

    public static string Authority(HttpRequestMessage request) => request.Headers.Host ?? HttpUris.Authority(request.RequestUri!);

    private static void AddCallerHeaders(List<KeyValuePair<string, string>> headers, HttpHeaders source)
    {
        foreach (var (name, values) in source.NonValidated)
        {
            if (Derived.Contains(name))
            {
                continue;
            }

            var separator = string.Equals(name, "Cookie", StringComparison.OrdinalIgnoreCase) ? "; " : ", ";
            headers.Add(new(name, string.Join(separator, values)));
        }
    }

    private static bool Contains(List<KeyValuePair<string, string>> headers, string name) =>
        headers.Exists(header => string.Equals(header.Key, name, StringComparison.OrdinalIgnoreCase));
}
