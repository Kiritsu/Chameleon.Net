using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Chameleon.Net.Tests.Support;

/// <summary>Kestrel on loopback, cleartext HTTP/2 only (prior knowledge).</summary>
internal sealed class KestrelHttp2Server : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly Uri _baseAddress;

    private KestrelHttp2Server(WebApplication app, Uri baseAddress)
    {
        _app = app;
        _baseAddress = baseAddress;
    }

    public static async Task<KestrelHttp2Server> StartAsync(Action<WebApplication> map, int maxStreamsPerConnection = 100)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Limits.Http2.MaxStreamsPerConnection = maxStreamsPerConnection;
            options.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http2);
        });

        var app = builder.Build();
        map(app);
        await app.StartAsync();

        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return new KestrelHttp2Server(app, new Uri(address));
    }

    public Uri Url(string pathAndQuery) => new(_baseAddress, pathAndQuery);

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}
