using System.Net;

namespace Chameleon.Net.WebSockets;

/// <summary>The server answered the WebSocket upgrade with something other than 101. Headers are kept because bot-management
/// rejections (e.g. a 403) are usually explained there rather than in the status.</summary>
public sealed class WebSocketUpgradeRejectedException : HttpRequestException
{
    public WebSocketUpgradeRejectedException(HttpStatusCode statusCode, IReadOnlyList<KeyValuePair<string, string>> responseHeaders)
        : base($"The server answered the WebSocket upgrade with HTTP {(int)statusCode} instead of 101.", null, statusCode)
    {
        ArgumentNullException.ThrowIfNull(responseHeaders);
        ResponseHeaders = responseHeaders;
    }

    public IReadOnlyList<KeyValuePair<string, string>> ResponseHeaders { get; }
}
