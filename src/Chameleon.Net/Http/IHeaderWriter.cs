using Chameleon.Net.Profiles;

namespace Chameleon.Net.Http;

/// <summary>Produces the final on-wire header sequence: profile order, casing per HTTP version, defaults merged under caller-set values.</summary>
public interface IHeaderWriter
{
    IReadOnlyList<KeyValuePair<string, string>> Order(HttpRequestMessage request, RequestKind kind, HeaderProfile profile, Version httpVersion);
}
