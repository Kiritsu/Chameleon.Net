namespace Chameleon.Net.Profiles;

/// <summary>Everything observable about a client, across layers, for one client/platform/version target.</summary>
public sealed record ClientProfile(
    ProfileIdentity Identity,
    TlsProfile Tls,
    Http2Profile Http2,
    HeaderProfile Headers,
    WebSocketProfile WebSocket,
    TransportProfile? Transport = null);

/// <summary>Structured metadata so selectors can filter by platform or client family ("any Android", "Chrome ≥ 130") instead of parsing names.</summary>
public sealed record ProfileIdentity(
    string Name,
    ClientPlatform Platform,
    string ClientFamily,
    string Version);

public enum ClientPlatform
{
    Unknown,
    Windows,
    MacOS,
    Linux,
    Android,
    IOS,
}
