using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Chameleon.Net.Tests.DependencyInjection;

public sealed class HttpClientFactoryTests
{
    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task NamedClientsShareOneHandlerAndItsConnections()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        var services = new ServiceCollection();
        services.AddHttpClient("api").UseChameleon(BuiltInProfiles.OkHttp4Android13);
        await using var provider = services.BuildServiceProvider();
        var factory = provider.GetRequiredService<IHttpClientFactory>();

        await factory.CreateClient("api").GetStringAsync(server.Url("/one"), CancellationToken);
        await factory.CreateClient("api").GetStringAsync(server.Url("/two"), CancellationToken);

        // The handler isn't rotated, so the second client reuses the first one's pooled connection, as one OkHttpClient would.
        Assert.Equal([0, 0], server.Requests.Select(static r => r.Connection));
        Assert.All(server.Requests, static r => Assert.Equal("okhttp/4.12.0", r.Header("User-Agent")));
    }

    [Fact]
    public async Task TypedClientUsesTheProfileAndTheContainerLogging()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        var logs = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddProvider(logs).SetMinimumLevel(LogLevel.Debug));
        services.AddHttpClient<ApiClient>().UseChameleon(BuiltInProfiles.Chromium152Windows);
        await using var provider = services.BuildServiceProvider();

        await provider.GetRequiredService<ApiClient>().Http.GetStringAsync(server.Url("/"), CancellationToken);

        Assert.Equal("\"Windows\"", Assert.Single(server.Requests).Header("sec-ch-ua-platform"));
        Assert.Contains(logs.Messages, static m => m.StartsWith("Connected to 127.0.0.1:", StringComparison.Ordinal) && m.Contains("chromium_152_windows", StringComparison.Ordinal));
    }

    [Fact]
    public void ConfigureCallbackWithoutAProfileFailsClearly()
    {
        var services = new ServiceCollection();
        services.AddHttpClient("api").UseChameleon(static (_, _) => { });
        using var provider = services.BuildServiceProvider();

        var exception = Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IHttpClientFactory>().CreateClient("api"));
        Assert.Contains("ProfileSelector", exception.Message, StringComparison.Ordinal);
    }

    /// <summary>Like one OkHttpClient used for REST and WebSockets: the connector resumes the TLS session of the HTTP client's requests.</summary>
    [Fact]
    public async Task WebSocketConnectorResumesTheHttpClientsTlsSession()
    {
        using var certificate = TestCertificates.SelfSigned();
        await using var server = await KestrelHttp2Server.StartAsync(static app =>
        {
            app.UseWebSockets();
            app.MapGet("/", static () => "ok");
            app.Map("/ws", static async context =>
            {
                using var socket = await context.WebSockets.AcceptWebSocketAsync();
                await socket.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure, null, context.RequestAborted);
            });
        }, certificate: certificate);
        var port = server.Url("/").Port;
        var logs = new CapturingLoggerProvider();
        var validator = new TrustAnyCertificate();
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddProvider(logs).SetMinimumLevel(LogLevel.Debug));
        services.AddHttpClient("api").UseChameleon(BuiltInProfiles.OkHttp4Android13, options => options.CertificateValidator = validator);
        services.AddChameleonWebSocketConnector(options => options.CertificateValidator = validator);
        await using var provider = services.BuildServiceProvider();

        Assert.Equal("ok", await provider.GetRequiredService<IHttpClientFactory>().CreateClient("api").GetStringAsync(new Uri($"https://127.0.0.1:{port}/"), CancellationToken));
        var connector = provider.GetRequiredService<IWebSocketConnector>();
        using var webSocket = await connector.ConnectAsync(new Uri($"wss://127.0.0.1:{port}/ws"), BuiltInProfiles.OkHttp4Android13, cancellationToken: CancellationToken);

        Assert.Same(provider.GetRequiredService<ChameleonWebSocketConnector>(), connector);
        Assert.Contains(logs.Messages, static m => m.StartsWith("WebSocket to wss://127.0.0.1:", StringComparison.Ordinal) && m.EndsWith("TLS session resumed: True", StringComparison.Ordinal));
    }

    private sealed class ApiClient(HttpClient http)
    {
        public HttpClient Http { get; } = http;
    }
}
