using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Chameleon.Net.Tests.Support;

/// <summary>Kestrel on loopback: cleartext HTTP/2 only (prior knowledge), or TLS when given a certificate.</summary>
internal sealed class KestrelHttp2Server : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly Uri _baseAddress;

    private KestrelHttp2Server(WebApplication app, Uri baseAddress)
    {
        _app = app;
        _baseAddress = baseAddress;
    }

    /// <param name="certificate">When set, TLS with this certificate (HTTP/1.1 and HTTP/2 via ALPN) instead of cleartext HTTP/2.</param>
    public static async Task<KestrelHttp2Server> StartAsync(Action<WebApplication> map, int maxStreamsPerConnection = 100, X509Certificate2? certificate = null)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Limits.Http2.MaxStreamsPerConnection = maxStreamsPerConnection;
            options.Listen(IPAddress.Loopback, 0, listen =>
            {
                if (certificate is null)
                {
                    listen.Protocols = HttpProtocols.Http2;
                }
                else
                {
                    listen.Protocols = HttpProtocols.Http1AndHttp2;
                    listen.UseHttps(certificate);
                }
            });
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
