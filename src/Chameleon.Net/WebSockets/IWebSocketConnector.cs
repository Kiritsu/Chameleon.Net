using System.Net.WebSockets;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.WebSockets;

/// <summary>Sends the profiled Upgrade request over the profiled TLS stream, then hands the stream to the BCL WebSocket implementation.</summary>
public interface IWebSocketConnector
{
    /// <exception cref="WebSocketException">The handshake failed. When the server answered with a status other than 101,
    /// <see cref="Exception.InnerException"/> is a <see cref="WebSocketUpgradeRejectedException"/> carrying the status and headers.</exception>
    Task<WebSocket> ConnectAsync(Uri uri, ClientProfile profile, ChameleonWebSocketOptions? options = null, CancellationToken cancellationToken = default);
}
