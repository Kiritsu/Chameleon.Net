using Microsoft.Extensions.Logging;

namespace Chameleon.Net;

internal static partial class Log
{
    public const string Category = "Chameleon.Net";

    [LoggerMessage(EventId = 1, Level = LogLevel.Debug, Message = "Connected to {Host}:{Port} with profile {Profile}, protocol {Protocol}, TLS session resumed: {Resumed}")]
    public static partial void Connected(ILogger logger, string host, int port, string profile, string protocol, bool resumed);

    [LoggerMessage(EventId = 2, Level = LogLevel.Warning, Message = "Connecting to {Host}:{Port} failed")]
    public static partial void ConnectFailed(ILogger logger, string host, int port, Exception exception);

    [LoggerMessage(EventId = 3, Level = LogLevel.Debug, Message = "Replaying {Method} {Uri} on another connection: {Reason}")]
    public static partial void Replaying(ILogger logger, string method, Uri? uri, string reason);

    [LoggerMessage(EventId = 4, Level = LogLevel.Debug, Message = "Following HTTP {Status} redirect to {Target}")]
    public static partial void Redirecting(ILogger logger, int status, Uri target);

    [LoggerMessage(EventId = 5, Level = LogLevel.Information, Message = "HTTP/2 connection to {Host} is going away ({Code}, last stream {LastStreamId})")]
    public static partial void GoAway(ILogger logger, string host, Http.Http2.Http2ErrorCode code, int lastStreamId);

    [LoggerMessage(EventId = 6, Level = LogLevel.Debug, Message = "HTTP/2 connection to {Host} closed")]
    public static partial void Http2Closed(ILogger logger, string host, Exception reason);

    [LoggerMessage(EventId = 7, Level = LogLevel.Debug, Message = "WebSocket to {Uri} upgraded with profile {Profile}, TLS session resumed: {Resumed}")]
    public static partial void WebSocketUpgraded(ILogger logger, Uri uri, string profile, bool resumed);

    [LoggerMessage(EventId = 8, Level = LogLevel.Warning, Message = "WebSocket upgrade to {Uri} rejected with HTTP {Status}")]
    public static partial void WebSocketRejected(ILogger logger, Uri uri, int status);
}
