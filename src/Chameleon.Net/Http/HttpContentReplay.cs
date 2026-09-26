namespace Chameleon.Net.Http;

internal static class HttpContentReplay
{
    /// <summary>Whether the request can be sent again after a connection turned out stale. OkHttp replays any body that isn't one-shot;
    /// here that means in-memory content, which serializes identically every time.</summary>
    public static bool IsReplayable(HttpContent? content) => content is null or ByteArrayContent or ReadOnlyMemoryContent;
}
