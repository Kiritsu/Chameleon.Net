using System.Net.WebSockets;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;

namespace Chameleon.Net.Tests.WebSockets;

/// <summary>Real network. Explicit: run with <c>dotnet test --solution Chameleon.Net.slnx -- --explicit only</c>.</summary>
public sealed class LiveWebSocketTests
{
    [Theory(Explicit = true)]
    [InlineData("wss://echo.websocket.org/")]
    public async Task EchoesOverProfiledTls(string url)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var webSocket = await new ChameleonWebSocketConnector()
            .ConnectAsync(new Uri(url), BuiltInProfiles.OkHttp4Android13, cancellationToken: cancellationToken);
        var payload = $"chameleon-{Guid.NewGuid()}";

        // Receive is pending before the send: over a blocking TLS stream this only works if reads and writes don't share a lock.
        var echoed = ReceiveUntilAsync(webSocket, payload, cancellationToken);
        await webSocket.SendTextAsync(payload, cancellationToken).WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);

        Assert.Equal(payload, await echoed.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken));
        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, cancellationToken);
    }

    // Some echo servers greet first; skip anything that isn't our payload.
    private static async Task<string> ReceiveUntilAsync(WebSocket webSocket, string expected, CancellationToken cancellationToken)
    {
        while (true)
        {
            var message = await webSocket.ReceiveTextAsync(cancellationToken);
            if (message == expected)
            {
                return message;
            }
        }
    }
}
