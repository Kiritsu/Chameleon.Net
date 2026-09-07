namespace Chameleon.Net.Profiles;

/// <summary>Upgrade request shape. <paramref name="PerMessageDeflateOffer"/> is the literal Sec-WebSocket-Extensions value, or null to not offer compression.</summary>
public sealed record WebSocketProfile(
    IReadOnlyList<string> HandshakeHeaderOrder,
    string? PerMessageDeflateOffer);
