using System.IO.Compression;
using System.Net;
using ZstdSharp;

namespace Chameleon.Net.Http;

internal static class ResponseFactory
{
    /// <param name="body">Null when the response has no body (HEAD, 204, 304, ...).</param>
    /// <param name="transparentDecompression">Decode gzip/deflate/br/zstd and drop Content-Encoding/Content-Length, as the client itself asked for them.</param>
    public static HttpResponseMessage Create(
        HttpRequestMessage request,
        int statusCode,
        Version version,
        string? reasonPhrase,
        IEnumerable<KeyValuePair<string, string>> headers,
        Stream? body,
        bool transparentDecompression)
    {
        var headerList = headers as IReadOnlyCollection<KeyValuePair<string, string>> ?? [.. headers];
        var decoder = transparentDecompression && body is not null ? Decoder(headerList) : null;

        var response = new HttpResponseMessage((HttpStatusCode)statusCode)
        {
            Version = version,
            ReasonPhrase = reasonPhrase,
            RequestMessage = request,
        };

        HttpContent content = body is null ? new ByteArrayContent([]) : new StreamContent(decoder is null ? body : decoder(body));
        foreach (var (name, value) in headerList)
        {
            if (decoder is not null && (IsHeader(name, "Content-Encoding") || IsHeader(name, "Content-Length")))
            {
                continue;
            }

            if (!response.Headers.TryAddWithoutValidation(name, value))
            {
                content.Headers.TryAddWithoutValidation(name, value);
            }
        }

        response.Content = content;
        return response;
    }

    private static Func<Stream, Stream>? Decoder(IEnumerable<KeyValuePair<string, string>> headers)
    {
        var codings = headers
            .Where(static header => IsHeader(header.Key, "Content-Encoding"))
            .SelectMany(static header => header.Value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            .ToList();

        return codings.Count != 1 ? null : codings[0].ToLowerInvariant() switch
        {
            "gzip" or "x-gzip" => static body => new GZipStream(body, CompressionMode.Decompress),
            "deflate" => static body => new ZLibStream(body, CompressionMode.Decompress),
            "br" => static body => new BrotliStream(body, CompressionMode.Decompress),
            "zstd" => static body => new DecompressionStream(body, leaveOpen: false),
            _ => null,
        };
    }

    private static bool IsHeader(string name, string expected) => string.Equals(name, expected, StringComparison.OrdinalIgnoreCase);
}
