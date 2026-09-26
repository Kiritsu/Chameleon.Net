using Chameleon.Net.Http;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Microsoft.Extensions.Logging;

namespace Chameleon.Net.Tests;

public sealed class LoggingTests
{
    [Fact]
    public async Task ConnectionsRetriesAndRedirectsAreLogged()
    {
        var provider = new CapturingLoggerProvider();
        using var loggerFactory = LoggerFactory.Create(builder => builder.AddProvider(provider).SetMinimumLevel(LogLevel.Debug));
        await using var server = new LoopbackHttpServer(static request => request.Path == "/start"
            ? Reply.Raw("HTTP/1.1 302 Found\r\nLocation: /end\r\nContent-Length: 0\r\n\r\n", close: true)
            : Reply.Ok("done"));
        using var client = new HttpClient(new ChameleonHttpMessageHandler(BuiltInProfiles.OkHttp4Android13, new ChameleonOptions { LoggerFactory = loggerFactory }));

        await client.GetStringAsync(server.Url("/start"), TestContext.Current.CancellationToken);

        Assert.Contains($"Connected to 127.0.0.1:{server.Port} with profile okhttp4_android_13, protocol http/1.1, TLS session resumed: False", provider.Messages);
        Assert.Contains(provider.Messages, static m => m.StartsWith("Following HTTP 302 redirect to http://127.0.0.1:", StringComparison.Ordinal));
        Assert.Contains(provider.Messages, static m => m.StartsWith("Replaying GET http://127.0.0.1:", StringComparison.Ordinal));
    }

}
