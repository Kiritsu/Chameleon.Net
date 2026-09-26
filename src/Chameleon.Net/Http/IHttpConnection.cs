using Chameleon.Net.Profiles;

namespace Chameleon.Net.Http;

/// <summary>One negotiated connection (HTTP/1.1 today, HTTP/2 later) bound to a single profile for its whole lifetime.</summary>
internal interface IHttpConnection : IDisposable
{
    bool IsReusable { get; }

    Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, RequestKind kind, string? cookieHeader, CancellationToken cancellationToken);
}

/// <summary>A pooled connection failed before any response byte arrived; the request is safe to replay on a fresh connection.</summary>
internal sealed class StaleConnectionException(Exception innerException)
    : Exception("A pooled connection was closed by the server.", innerException);
