using System.Net.WebSockets;
using System.Text;

namespace Chameleon.Net.Tests.Support;

internal static class WebSocketExtensions
{
    public static Task SendTextAsync(this WebSocket webSocket, string text, CancellationToken cancellationToken) =>
        webSocket.SendAsync(Encoding.UTF8.GetBytes(text).AsMemory(), WebSocketMessageType.Text, true, cancellationToken).AsTask();

    public static async Task<string> ReceiveTextAsync(this WebSocket webSocket, CancellationToken cancellationToken)
    {
        using var message = new MemoryStream();
        var buffer = new byte[16 * 1024];
        ValueWebSocketReceiveResult result;
        do
        {
            result = await webSocket.ReceiveAsync(buffer.AsMemory(), cancellationToken);
            message.Write(buffer, 0, result.Count);
        }
        while (!result.EndOfMessage);

        Assert.Equal(WebSocketMessageType.Text, result.MessageType);
        return Encoding.UTF8.GetString(message.ToArray());
    }
}
