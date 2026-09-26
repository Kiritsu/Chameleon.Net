namespace Chameleon.Net.WebSockets;

public sealed class ChameleonWebSocketOptions
{
    /// <summary>Extra request headers, e.g. <c>Authorization</c> or <c>Origin</c>. Headers the profile's handshake order doesn't list are sent first, in this order.
    /// The handshake headers (<c>Host</c>, <c>Upgrade</c>, <c>Connection</c>, <c>Sec-WebSocket-*</c>) are reserved.</summary>
    public IList<KeyValuePair<string, string>> Headers { get; } = [];

    /// <summary>Offered in <c>Sec-WebSocket-Protocol</c>; the server may pick one.</summary>
    public IList<string> SubProtocols { get; } = [];

    /// <summary>Zero (disabled) by default: OkHttp and browsers send no keep-alive frames unless configured to, and unsolicited ones are observable.</summary>
    public TimeSpan KeepAliveInterval { get; set; } = TimeSpan.Zero;
}
