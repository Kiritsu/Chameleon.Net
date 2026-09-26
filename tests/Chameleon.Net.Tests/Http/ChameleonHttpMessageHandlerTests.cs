using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;

namespace Chameleon.Net.Tests.Http;

/// <summary>HTTP/1.1 behaviour against a loopback http:// server — the TLS layer is covered elsewhere.</summary>
public sealed class ChameleonHttpMessageHandlerTests
{
    private static readonly ClientProfile Profile = BuiltInProfiles.OkHttp4Android13;

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task GetFollowsProfileHeaderOrder()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("hi"));
        using var client = Client();
        using var request = new HttpRequestMessage(HttpMethod.Get, server.Url("/path?q=1"));
        request.Headers.Add("X-App", "1");

        using var response = await client.SendAsync(request, CancellationToken);

        var sent = Assert.Single(server.Requests);
        Assert.Equal("GET /path?q=1 HTTP/1.1", sent.RequestLine);
        Assert.Equal(["X-App", "Host", "Connection", "Accept-Encoding", "User-Agent"], sent.HeaderNames);
        Assert.Equal($"127.0.0.1:{server.Port}", sent.Header("Host"));
        Assert.Equal("Keep-Alive", sent.Header("Connection"));
        Assert.Equal("okhttp/4.12.0", sent.Header("User-Agent"));
        Assert.Equal("hi", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task PostWithKnownLengthSendsContentLength()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = Client();

        using var response = await client.PostAsync(server.Url("/items"),
            new StringContent("""{"a":1}""", Encoding.UTF8, "application/json"), CancellationToken);

        var sent = Assert.Single(server.Requests);
        Assert.Equal(["Content-Type", "Content-Length", "Host", "Connection", "Accept-Encoding", "User-Agent"], sent.HeaderNames);
        Assert.Equal("7", sent.Header("Content-Length"));
        Assert.Equal("""{"a":1}""", sent.BodyText);
    }

    [Fact]
    public async Task PostWithUnknownLengthIsChunked()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = Client();
        var payload = string.Concat(Enumerable.Repeat("0123456789", 5_000));

        using var response = await client.PostAsync(server.Url("/upload"), new UnknownLengthContent(Encoding.UTF8.GetBytes(payload)), CancellationToken);

        var sent = Assert.Single(server.Requests);
        Assert.Equal("chunked", sent.Header("Transfer-Encoding"));
        Assert.Null(sent.Header("Content-Length"));
        Assert.Equal(payload, sent.BodyText);
    }

    [Fact]
    public async Task PostWithoutContentSendsZeroLength()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = Client();

        using var response = await client.PostAsync(server.Url("/ping"), null, CancellationToken);

        Assert.Equal("0", Assert.Single(server.Requests).Header("Content-Length"));
    }

    [Theory]
    [InlineData("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world", false)]
    [InlineData("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nTrailer: x\r\n\r\n", false)]
    [InlineData("HTTP/1.1 200 OK\r\n\r\nhello world", true)]
    public async Task ReadsEveryBodyFraming(string response, bool closeDelimited)
    {
        await using var server = new LoopbackHttpServer(_ => Reply.Raw(response, close: closeDelimited));
        using var client = Client();

        Assert.Equal("hello world", await client.GetStringAsync(server.Url("/"), CancellationToken));
    }

    [Fact]
    public async Task GzipIsDecodedWhenTheProfileAskedForIt()
    {
        await using var server = new LoopbackHttpServer(static _ => GzipReply("hello gzip"));
        using var client = Client();

        using var response = await client.GetAsync(server.Url("/"), CancellationToken);

        Assert.Equal("hello gzip", await response.Content.ReadAsStringAsync(CancellationToken));
        Assert.Empty(response.Content.Headers.ContentEncoding);
    }

    [Fact]
    public async Task CallerSetAcceptEncodingLeavesBodyEncoded()
    {
        await using var server = new LoopbackHttpServer(static _ => GzipReply("hello gzip"));
        using var client = Client();
        using var request = new HttpRequestMessage(HttpMethod.Get, server.Url("/"));
        request.Headers.AcceptEncoding.Add(new StringWithQualityHeaderValue("gzip"));

        using var response = await client.SendAsync(request, CancellationToken);
        var body = await response.Content.ReadAsByteArrayAsync(CancellationToken);

        Assert.Equal([0x1F, 0x8B], body[..2]);
        Assert.Equal(["gzip"], response.Content.Headers.ContentEncoding);
    }

    [Fact]
    public async Task KeepAliveReusesTheConnection()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = Client();

        await client.GetStringAsync(server.Url("/1"), CancellationToken);
        await client.GetStringAsync(server.Url("/2"), CancellationToken);

        Assert.Equal([0, 0], server.Requests.Select(static r => r.Connection));
    }

    [Fact]
    public async Task ConnectionCloseOpensANewConnection()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok", "Connection: close"));
        using var client = Client();

        await client.GetStringAsync(server.Url("/1"), CancellationToken);
        await client.GetStringAsync(server.Url("/2"), CancellationToken);

        Assert.Equal([0, 1], server.Requests.Select(static r => r.Connection));
    }

    [Fact]
    public async Task SilentlyClosedPooledConnectionIsRetried()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Raw("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", close: true));
        using var client = Client();

        await client.GetStringAsync(server.Url("/1"), CancellationToken);
        Assert.Equal("ok", await client.GetStringAsync(server.Url("/2"), CancellationToken));

        Assert.Equal([0, 1], server.Requests.Select(static r => r.Connection));
    }

    [Theory]
    [InlineData(301, "GET", "GET", false)]
    [InlineData(302, "POST", "GET", false)]
    [InlineData(303, "POST", "GET", false)]
    [InlineData(307, "POST", "POST", true)]
    [InlineData(308, "PUT", "PUT", true)]
    public async Task FollowsRedirects(int status, string method, string expectedMethod, bool bodyKept)
    {
        await using var server = new LoopbackHttpServer(request => request.Path == "/start"
            ? Reply.Status($"{status} Redirect", string.Empty, "Location: /end")
            : Reply.Ok("done"));
        using var client = Client();
        using var request = new HttpRequestMessage(new HttpMethod(method), server.Url("/start"))
        {
            Content = method == "GET" ? null : new StringContent("payload"),
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "secret");

        using var response = await client.SendAsync(request, CancellationToken);

        var followed = server.Requests[^1];
        Assert.Equal($"{expectedMethod} /end HTTP/1.1", followed.RequestLine);
        Assert.Equal(bodyKept ? "payload" : string.Empty, followed.BodyText);
        Assert.Null(followed.Header("Authorization"));
        Assert.Equal("/end", response.RequestMessage!.RequestUri!.AbsolutePath);
        Assert.Equal("done", await response.Content.ReadAsStringAsync(CancellationToken));
    }

    [Fact]
    public async Task RedirectLimitReturnsTheLastRedirect()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Status("302 Found", string.Empty, "Location: /loop"));
        using var client = Client(new ChameleonOptions { MaxAutomaticRedirections = 2 });

        using var response = await client.GetAsync(server.Url("/loop"), CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal(3, server.Requests.Count);
    }

    [Fact]
    public async Task RedirectsCanBeDisabled()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.Status("302 Found", string.Empty, "Location: /elsewhere"));
        using var client = Client(new ChameleonOptions { AllowAutoRedirect = false });

        using var response = await client.GetAsync(server.Url("/"), CancellationToken);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Single(server.Requests);
    }

    [Fact]
    public async Task CookiesAreStoredAndSentInProfilePosition()
    {
        await using var server = new LoopbackHttpServer(static request => request.Path == "/login"
            ? Reply.Ok("in", "Set-Cookie: session=abc; Path=/")
            : Reply.Ok("me"));
        using var client = Client(new ChameleonOptions { Cookies = new CookieContainer() });

        await client.GetStringAsync(server.Url("/login"), CancellationToken);
        await client.GetStringAsync(server.Url("/me"), CancellationToken);

        var second = server.Requests[1];
        Assert.Equal("session=abc", second.Header("Cookie"));
        Assert.Equal(["Host", "Connection", "Accept-Encoding", "Cookie", "User-Agent"], second.HeaderNames);
    }

    [Fact]
    public async Task RequestKindSelectsTheProfileOverride()
    {
        var browserLike = Profile with
        {
            Headers = Profile.Headers with
            {
                Overrides = new Dictionary<RequestKind, IReadOnlyList<string>>
                {
                    [RequestKind.Navigate] = ["User-Agent", "Accept-Encoding", "Connection", "Host"],
                },
            },
        };
        await using var server = new LoopbackHttpServer(static _ => Reply.Ok("ok"));
        using var client = new HttpClient(new ChameleonHttpMessageHandler(browserLike));
        using var navigate = new HttpRequestMessage(HttpMethod.Get, server.Url("/"));
        navigate.Options.Set(ChameleonRequestOptions.Kind, RequestKind.Navigate);

        (await client.SendAsync(navigate, CancellationToken)).Dispose();
        await client.GetStringAsync(server.Url("/"), CancellationToken);

        Assert.Equal(["User-Agent", "Accept-Encoding", "Connection", "Host"], server.Requests[0].HeaderNames);
        Assert.Equal(["Host", "Connection", "Accept-Encoding", "User-Agent"], server.Requests[1].HeaderNames);
    }

    [Fact]
    public async Task InterimResponsesAreSkipped()
    {
        await using var server = new LoopbackHttpServer(static _ =>
            Reply.Raw("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        using var client = Client();

        Assert.Equal("ok", await client.GetStringAsync(server.Url("/"), CancellationToken));
    }

    [Fact]
    public async Task HeadResponseHasNoBodyAndKeepsTheConnection()
    {
        await using var server = new LoopbackHttpServer(static request => request.Method == "HEAD"
            ? Reply.Raw("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n")
            : Reply.Ok("after"));
        using var client = Client();

        using var head = await client.SendAsync(new HttpRequestMessage(HttpMethod.Head, server.Url("/")), CancellationToken);
        var after = await client.GetStringAsync(server.Url("/"), CancellationToken);

        Assert.Equal(5, head.Content.Headers.ContentLength);
        Assert.Equal("after", after);
        Assert.Equal([0, 0], server.Requests.Select(static r => r.Connection));
    }

    [Fact]
    public async Task CancellationAbortsAPendingRequest()
    {
        await using var server = new LoopbackHttpServer(static _ => Reply.None);
        using var client = Client();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
        timeout.CancelAfter(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetAsync(server.Url("/"), timeout.Token));
    }

    [Fact]
    public void UnsupportedOptionsAreRejected()
    {
        Assert.Throws<NotSupportedException>(() => new ChameleonHttpMessageHandler(Profile, new ChameleonOptions { Proxy = new WebProxy("http://proxy") }));
    }

    private static HttpClient Client(ChameleonOptions? options = null) => new(new ChameleonHttpMessageHandler(Profile, options));

    private static Reply GzipReply(string body)
    {
        using var compressed = new MemoryStream();
        using (var gzip = new GZipStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes(body));
        }

        var head = $"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {compressed.Length}\r\n\r\n";
        return new Reply([.. Encoding.Latin1.GetBytes(head), .. compressed.ToArray()]);
    }

    /// <summary>Content whose length can't be computed up front, like a pipe or a generator.</summary>
    private sealed class UnknownLengthContent(byte[] data) : HttpContent
    {
        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            await stream.WriteAsync(data.AsMemory(0, data.Length / 2));
            await stream.WriteAsync(data.AsMemory(data.Length / 2));
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }
}
