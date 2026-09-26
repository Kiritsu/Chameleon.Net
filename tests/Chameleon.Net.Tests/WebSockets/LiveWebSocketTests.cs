using System.Net.WebSockets;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;

namespace Chameleon.Net.Tests.WebSockets;

/// <summary>Real network. Explicit: run with <c>dotnet test --solution Chameleon.Net.slnx -- --explicit only</c>.</summary>
public sealed class LiveWebSocketTests
{
    /// <summary>echo.websocket.org runs on Fly; ws.ifelse.io is behind Cloudflare, the main target.</summary>
    [Theory(Explicit = true)]
    [InlineData("wss://echo.websocket.org/", "okhttp")]
    [InlineData("wss://ws.ifelse.io/", "okhttp")]
    [InlineData("wss://ws.ifelse.io/", "chromium")]
    [InlineData("wss://ws.ifelse.io/", "firefox")]
    [InlineData("wss://ws.ifelse.io/", "edge")]
    public async Task EchoesOverProfiledTls(string url, string profileName)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var webSocket = await new ChameleonWebSocketConnector()
            .ConnectAsync(new Uri(url), Profile(profileName), cancellationToken: cancellationToken);
        var payload = $"chameleon-{Guid.NewGuid()}";

        // Receive is pending before the send: over a blocking TLS stream this only works if reads and writes don't share a lock.
        var echoed = ReceiveUntilAsync(webSocket, payload, cancellationToken);
        await webSocket.SendTextAsync(payload, cancellationToken).WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);

        Assert.Equal(payload, await echoed.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken));
        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, cancellationToken);
    }

    /// <summary>A real Cloudflare-fronted API: Kraken greets every new connection with its system status.</summary>
    [Fact(Explicit = true)]
    public async Task CloudflareFrontedApiAcceptsTheOkHttpHandshake()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var webSocket = await new ChameleonWebSocketConnector()
            .ConnectAsync(new Uri("wss://ws.kraken.com/"), BuiltInProfiles.OkHttp4Android13, cancellationToken: cancellationToken);

        var greeting = await webSocket.ReceiveTextAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);

        Assert.Contains("systemStatus", greeting, StringComparison.Ordinal);
        await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, cancellationToken);
    }

    private static ClientProfile Profile(string name) => name switch
    {
        "okhttp" => BuiltInProfiles.OkHttp4Android13,
        "chromium" => BuiltInProfiles.Chromium152Windows,
        "firefox" => BuiltInProfiles.Firefox156Windows,
        _ => BuiltInProfiles.Edge153Windows,
    };

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
