namespace Chameleon.Net.Profiles;

/// <summary>Header order (JA4H), HTTP/1.1 casing, and the client's default header values.
/// <paramref name="HeaderOrder"/> and <paramref name="DefaultHeaders"/> apply to every request; browsers override them per <see cref="RequestKind"/>
/// (a navigation, a fetch() and a WebSocket handshake send different headers), native clients leave the overrides empty.</summary>
/// <param name="DefaultHeaderOverrides">Replaces <paramref name="DefaultHeaders"/> entirely for the given kinds.</param>
/// <param name="Http2OnlyHeaders">Default headers left out on HTTP/1.1 connections (Chrome sends <c>priority</c> only over HTTP/2).</param>
public sealed record HeaderProfile(
    IReadOnlyList<string> HeaderOrder,
    IReadOnlyDictionary<RequestKind, IReadOnlyList<string>> Overrides,
    HeaderCasing Http1Casing,
    IReadOnlyDictionary<string, string> DefaultHeaders,
    HeaderOrderMode OrderMode = HeaderOrderMode.ProfileOrder,
    IReadOnlyDictionary<RequestKind, IReadOnlyDictionary<string, string>>? DefaultHeaderOverrides = null,
    IReadOnlyList<string>? Http2OnlyHeaders = null)
{
    public IReadOnlyList<string> OrderFor(RequestKind kind) => Overrides.TryGetValue(kind, out var order) ? order : HeaderOrder;

    public IEnumerable<KeyValuePair<string, string>> DefaultsFor(RequestKind kind, bool http2)
    {
        var defaults = DefaultHeaderOverrides is not null && DefaultHeaderOverrides.TryGetValue(kind, out var overrides) ? overrides : DefaultHeaders;
        return http2 || Http2OnlyHeaders is null
            ? defaults
            : defaults.Where(header => !Http2OnlyHeaders.Contains(header.Key, StringComparer.OrdinalIgnoreCase));
    }
}

public enum HeaderOrderMode
{
    /// <summary>Every header listed in the profile takes its profile position, whoever set it; unlisted headers come first (browsers).</summary>
    ProfileOrder,

    /// <summary>Headers the caller set keep the caller's order and come first, even listed ones like User-Agent; the headers the client
    /// adds itself follow in profile order (OkHttp's BridgeInterceptor only fills in what is missing).</summary>
    CallerFirst,
}

public enum RequestKind
{
    Navigate,
    Fetch,
    Xhr,
    WebSocket,
}

public enum HeaderCasing
{
    AsSpecified,
    TitleCase,
    LowerCase,
}
