namespace Chameleon.Net.Profiles;

/// <summary>Upgrade request shape. <paramref name="PerMessageDeflateOffer"/> is the literal Sec-WebSocket-Extensions value, or null to not offer compression.
/// <paramref name="Alpn"/> replaces the TLS profile's ALPN list on WebSocket connections (OkHttp forces http/1.1 there); null keeps it.</summary>
public sealed record WebSocketProfile(
    IReadOnlyList<string> HandshakeHeaderOrder,
    string? PerMessageDeflateOffer,
    IReadOnlyList<string>? Alpn = null);
