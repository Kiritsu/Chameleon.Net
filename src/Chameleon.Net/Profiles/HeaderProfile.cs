namespace Chameleon.Net.Profiles;

/// <summary>Header order (JA4H), HTTP/1.1 casing, and the client's default header values.
/// <paramref name="HeaderOrder"/> applies to every request; browsers override it per <see cref="RequestKind"/>, native clients leave <paramref name="Overrides"/> empty.</summary>
public sealed record HeaderProfile(
    IReadOnlyList<string> HeaderOrder,
    IReadOnlyDictionary<RequestKind, IReadOnlyList<string>> Overrides,
    HeaderCasing Http1Casing,
    IReadOnlyDictionary<string, string> DefaultHeaders);

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
