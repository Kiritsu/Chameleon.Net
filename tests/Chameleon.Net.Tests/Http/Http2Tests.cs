using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Chameleon.Net.Tests.Http;

/// <summary>HTTP/2 correctness against Kestrel over cleartext (prior knowledge) — the TLS/ALPN path is covered by the live tests.</summary>
public sealed class Http2Tests
{
    private const int LargeDownload = 20 * 1024 * 1024;

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task GetUsesHttp2()
    {
        await using var server = await StartAsync();
        using var client = Client();

        using var response = await client.GetAsync(server.Url("/hello"), CancellationToken);

        Assert.Equal(HttpVersion.Version20, response.Version);
        Assert.Equal("hello h2", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task ConcurrentRequestsShareOneConnectionWithinTheServerStreamLimit()
    {
        await using var server = await StartAsync(maxStreamsPerConnection: 5);
        using var client = Client();

        var connectionIds = await Task.WhenAll(Enumerable.Range(0, 50).Select(_ => client.GetStringAsync(server.Url("/connection"), CancellationToken)));

        Assert.Single(connectionIds.Distinct());
    }

    [Fact]
    public async Task LargeUploadIsFlowControlled()
    {
        await using var server = await StartAsync();
        using var client = Client();
        var payload = RandomNumberGenerator.GetBytes(5 * 1024 * 1024);

        using var response = await client.PostAsync(server.Url("/sha256"), new ByteArrayContent(payload), CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(payload)), await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task DownloadLargerThanTheReceiveWindowCompletes()
    {
        await using var server = await StartAsync();
        using var client = Client();

        var body = await client.GetByteArrayAsync(server.Url($"/bytes?size={LargeDownload}"), CancellationToken);

        Assert.Equal(LargeDownload, body.Length);
        Assert.True(body.Select(static (value, index) => value == (byte)(index % 251)).All(static ok => ok));
    }

    [Fact]
    public async Task TrailersAreExposedAfterTheBody()
    {
        await using var server = await StartAsync();
        using var client = Client();

        using var response = await client.GetAsync(server.Url("/trailers"), CancellationToken);
        var body = await response.Content.ReadAsStringAsync(CancellationToken);

        Assert.Equal("body", body);
        Assert.Equal(["done"], response.TrailingHeaders.GetValues("x-trailer"));
    }

    [Fact]
    public async Task GzipIsDecodedWhenTheProfileAskedForIt()
    {
        await using var server = await StartAsync();
        using var client = Client();

        using var response = await client.GetAsync(server.Url("/gzip"), CancellationToken);

        Assert.Equal("hello gzip", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Empty(response.Content.Headers.ContentEncoding);
    }

    [Fact]
    public async Task HeadAndNoContentHaveNoBody()
    {
        await using var server = await StartAsync();
        using var client = Client();

        using var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, server.Url("/hello")), CancellationToken);
        using var noContent = await client.GetAsync(server.Url("/empty"), CancellationToken);

        Assert.Empty(await head.Content.ReadAsByteArrayAsync(CancellationToken));
        Assert.Equal(HttpStatusCode.NoContent, noContent.StatusCode);
        Assert.Empty(await noContent.Content.ReadAsByteArrayAsync(CancellationToken));
    }

    [Fact]
    public async Task CancellationResetsOnlyThatStream()
    {
        await using var server = await StartAsync();
        using var client = Client();
        var before = await client.GetStringAsync(server.Url("/connection"), CancellationToken);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
        timeout.CancelAfter(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetAsync(server.Url("/hang"), timeout.Token));
        var after = await client.GetStringAsync(server.Url("/connection"), CancellationToken);

        Assert.Equal(before, after);
    }

    [Fact]
    public async Task DisposingAnUnreadBodyResetsTheStreamAndKeepsTheConnection()
    {
        await using var server = await StartAsync();
        using var client = Client();

        using (var response = await client.GetAsync(server.Url($"/bytes?size={LargeDownload}"), HttpCompletionOption.ResponseHeadersRead, CancellationToken))
        {
            await using var body = await response.Content.ReadAsStreamAsync(CancellationToken);
            await body.ReadExactlyAsync(new byte[1024], CancellationToken);
        }

        Assert.Equal("hello h2", await client.GetStringAsync(server.Url("/hello"), CancellationToken));
    }

    private static HttpClient Client() => new(new ChameleonHttpMessageHandler(BuiltInProfiles.OkHttp4Android13))
    {
        DefaultRequestVersion = HttpVersion.Version20,
        DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact,
    };

    private static Task<KestrelHttp2Server> StartAsync(int maxStreamsPerConnection = 100) => KestrelHttp2Server.StartAsync(static app =>
    {
        app.MapMethods("/hello", ["GET", "HEAD"], static () => "hello h2");
        app.MapGet("/connection", static (HttpContext context) => context.Connection.Id);
        app.MapGet("/empty", static () => Results.NoContent());
        app.MapGet("/hang", static async (HttpContext context) => await Task.Delay(Timeout.Infinite, context.RequestAborted));
        // Written explicitly: a HttpContext-only lambda returning Task<string> binds to RequestDelegate and its result is dropped.
        app.MapPost("/sha256", static async (HttpContext context) => await context.Response.WriteAsync(
            Convert.ToHexStringLower(await SHA256.HashDataAsync(context.Request.Body, context.RequestAborted)), context.RequestAborted));
        app.MapGet("/bytes", static async (HttpContext context, int size) =>
        {
            var chunk = new byte[64 * 1024];
            for (var offset = 0; offset < size; offset += chunk.Length)
            {
                var length = Math.Min(chunk.Length, size - offset);
                for (var i = 0; i < length; i++)
                {
                    chunk[i] = (byte)((offset + i) % 251);
                }

                await context.Response.Body.WriteAsync(chunk.AsMemory(0, length), context.RequestAborted);
            }
        });
        app.MapGet("/trailers", static async (HttpContext context) =>
        {
            context.Response.DeclareTrailer("x-trailer");
            await context.Response.WriteAsync("body", context.RequestAborted);
            context.Response.AppendTrailer("x-trailer", "done");
        });
        app.MapGet("/gzip", static async (HttpContext context) =>
        {
            using var compressed = new MemoryStream();
            await using (var gzip = new GZipStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
            {
                await gzip.WriteAsync(Encoding.UTF8.GetBytes("hello gzip"), context.RequestAborted);
            }

            context.Response.Headers.ContentEncoding = "gzip";
            await context.Response.Body.WriteAsync(compressed.ToArray(), context.RequestAborted);
        });
    }, maxStreamsPerConnection);
}
