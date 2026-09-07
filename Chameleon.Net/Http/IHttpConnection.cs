using Chameleon.Net.Profiles;

namespace Chameleon.Net.Http;

/// <summary>One negotiated connection (HTTP/1.1 or HTTP/2) bound to a single profile for its whole lifetime.</summary>
public interface IHttpConnection : IAsyncDisposable
{
    bool IsReusable { get; }

    ValueTask<HttpResponseMessage> SendAsync(HttpRequestMessage request, RequestKind kind, CancellationToken cancellationToken);
}
