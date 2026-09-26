using System.Text;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;

namespace Chameleon.Net.Tests.Http;

/// <summary>Keep-alive behaviour modelled on OkHttp's ConnectionPool.</summary>
public sealed class ConnectionPoolTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task KeepsAtMostFiveIdleConnections()
    {
        using var allArrived = new CountdownEvent(7);
        await using var server = new LoopbackHttpServer(_ =>
        {
            // Hold every response until all seven requests are in flight, so seven connections exist at once.
            allArrived.Signal();
            allArrived.Wait(TimeSpan.FromSeconds(10));
            return Reply.Ok("ok");
        });
        using var client = Client();

        await Task.WhenAll(Enumerable.Range(0, 7).Select(i => client.GetStringAsync(server.Url($"/{i}"), CancellationToken)));

        Assert.Equal(7, server.Requests.Select(static r => r.Connection).Distinct().Count());
        await WaitUntilAsync(() => server.ClientClosedConnections == 2);
        await Task.Delay(200, CancellationToken);
        Assert.Equal(2, server.ClientClosedConnections);
    }

    [Fact]
    public async Task InMemoryBodyIsReplayedWhenThePooledConnectionIsStale()
    {
        await using var server = new LoopbackHttpServer(static request => request.Path == "/first"
            ? Reply.Raw("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", close: true)
            : Reply.Ok(request.BodyText));
        using var client = Client();

        await client.GetStringAsync(server.Url("/first"), CancellationToken);
        using var response = await client.PostAsync(server.Url("/echo"), new StringContent("payload"), CancellationToken);

        Assert.Equal("payload", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Equal([0, 1], server.Requests.Select(static r => r.Connection));
    }

    [Fact]
    public async Task StreamedBodyIsNotReplayed()
    {
        await using var server = new LoopbackHttpServer(static request => request.Path == "/first"
            ? Reply.Raw("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", close: true)
            : Reply.Ok("unreachable"));
        using var client = Client();

        await client.GetStringAsync(server.Url("/first"), CancellationToken);
        var streamed = new StreamContent(new NonSeekableStream(Encoding.UTF8.GetBytes("payload")));

        await Assert.ThrowsAsync<HttpRequestException>(() => client.PostAsync(server.Url("/echo"), streamed, CancellationToken));
    }

    private static HttpClient Client() => new(new ChameleonHttpMessageHandler(BuiltInProfiles.OkHttp4Android13));

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(15);
        while (!condition() && DateTime.UtcNow < deadline)
        {
            await Task.Delay(50, CancellationToken);
        }
    }

    private sealed class NonSeekableStream(byte[] data) : MemoryStream(data)
    {
        public override bool CanSeek => false;
    }
}
