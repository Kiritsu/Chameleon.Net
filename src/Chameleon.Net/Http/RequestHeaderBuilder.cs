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

/// <summary>Assembles the headers the client would send, the way OkHttp's BridgeInterceptor does: the caller's headers, then what the
/// client adds itself — body framing, Host, cookies and the profile's defaults — with the profile deciding the final order.</summary>
internal static class RequestHeaderBuilder
{
    /// <summary>Always (re)written by the client from the request body, whatever the caller set.</summary>
    private static readonly FrozenSet<string> Framing =
        FrozenSet.Create(StringComparer.OrdinalIgnoreCase, "Content-Type", "Content-Length", "Transfer-Encoding");

    public static RequestHeaderPlan Build(HttpRequestMessage request, ClientProfile profile, RequestKind kind, string? cookieHeader, bool http2)
    {
        var caller = new List<KeyValuePair<string, string>>();
        var client = new List<KeyValuePair<string, string>>();

        AddCallerHeaders(caller, request.Headers);

        long? contentLength = null;
        var chunked = false;
        if (request.Content is { } content)
        {
            AddCallerHeaders(caller, content.Headers);
            if (content.Headers.ContentType is { } contentType)
            {
                client.Add(new("Content-Type", contentType.ToString()));
            }

            contentLength = content.Headers.ContentLength;
            chunked = contentLength is null;
        }
        else if (request.Method == HttpMethod.Post || request.Method == HttpMethod.Put || request.Method == HttpMethod.Patch)
        {
            contentLength = 0;
        }

        if (contentLength is { } length)
        {
            client.Add(new("Content-Length", length.ToString(CultureInfo.InvariantCulture)));
        }

        if (chunked)
        {
            client.Add(new("Transfer-Encoding", "chunked"));
        }

        if (!Contains(caller, "Host"))
        {
            client.Add(new("Host", Authority(request)));
        }

        if (!string.IsNullOrEmpty(cookieHeader) && !Contains(caller, "Cookie"))
        {
            client.Add(new("Cookie", cookieHeader));
        }

        // Like OkHttp, only decode bodies transparently when the Accept-Encoding came from the client, not the caller.
        var transparentDecompression = false;
        foreach (var (name, value) in profile.Headers.DefaultsFor(kind, http2))
        {
            if (Contains(caller, name) || Contains(client, name))
            {
                continue;
            }

            client.Add(new(name, value));
            transparentDecompression |= string.Equals(name, "Accept-Encoding", StringComparison.OrdinalIgnoreCase);
        }

        return new RequestHeaderPlan(
            HeaderOrdering.Order(caller, client, profile.Headers.OrderFor(kind), profile.Headers.Http1Casing, profile.Headers.OrderMode),
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
            if (Framing.Contains(name))
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
