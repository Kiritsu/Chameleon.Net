using System.Net.WebSockets;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.WebSockets;

/// <summary>Sends the profiled Upgrade request over the profiled TLS stream, then hands the stream to the BCL WebSocket implementation.</summary>
public interface IWebSocketConnector
{
    Task<WebSocket> ConnectAsync(Uri uri, ClientProfile profile, ChameleonOptions? options, CancellationToken cancellationToken);
}
