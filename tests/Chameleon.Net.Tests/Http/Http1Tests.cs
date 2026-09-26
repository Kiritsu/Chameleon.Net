using System.Text;
using Chameleon.Net.Http;
using Chameleon.Net.Http.Http1;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Tests.Http;

public sealed class Http1Tests
{
    private static readonly string[] OkHttpOrder = ["Content-Type", "Host", "Connection", "Accept-Encoding", "User-Agent"];

    [Fact]
    public void UnlistedHeadersComeFirstInOriginalOrder()
    {
        var ordered = HeaderOrdering.Order(
        [
            new("user-agent", "ua"),
            new("X-B", "b"),
            new("host", "h"),
            new("X-A", "a"),
            new("Accept-Encoding", "gzip"),
        ], OkHttpOrder, HeaderCasing.AsSpecified);

        Assert.Equal(["X-B", "X-A", "Host", "Accept-Encoding", "User-Agent"], ordered.Select(static h => h.Key));
    }

    [Theory]
    [InlineData(HeaderCasing.AsSpecified, "x-custom-header", "user-agent", "x-custom-header", "User-Agent")]
    [InlineData(HeaderCasing.TitleCase, "x-CUSTOM-header", "user-agent", "X-Custom-Header", "User-Agent")]
    [InlineData(HeaderCasing.LowerCase, "X-Custom-Header", "User-Agent", "x-custom-header", "user-agent")]
    public void CasingIsApplied(HeaderCasing casing, string unlisted, string listed, string expectedUnlisted, string expectedListed)
    {
        var ordered = HeaderOrdering.Order([new(unlisted, "1"), new(listed, "2")], OkHttpOrder, casing);

        Assert.Equal([expectedUnlisted, expectedListed], ordered.Select(static h => h.Key));
    }

    [Fact]
    public void RequestHeadIsWrittenVerbatim()
    {
        var head = Http1RequestHead.Encode("GET", "/a?b=c", [new("Host", "example.com"), new("X-Empty", "")]);

        Assert.Equal("GET /a?b=c HTTP/1.1\r\nHost: example.com\r\nX-Empty: \r\n\r\n", Encoding.Latin1.GetString(head));
    }

    [Fact]
    public void ResponseHeadIsParsed()
    {
        var head = Http1ResponseHead.Parse("HTTP/1.1 101 Switching Protocols\r\nUpgrade:websocket\r\nX-Spaced: \t padded \t"u8);

        Assert.Equal(new Version(1, 1), head.Version);
        Assert.Equal(101, head.StatusCode);
        Assert.Equal("Switching Protocols", head.ReasonPhrase);
        Assert.Equal("websocket", head.GetValue("upgrade"));
        Assert.Equal("padded", head.GetValue("X-Spaced"));
    }

    [Fact]
    public void ResponseWithoutReasonPhraseIsAccepted()
    {
        Assert.Equal(string.Empty, Http1ResponseHead.Parse("HTTP/1.1 204"u8).ReasonPhrase);
    }

    [Theory]
    [InlineData("HTTP/2 200 OK")]
    [InlineData("HTTP/1.1 20 OK")]
    [InlineData("HTTP/1.1 200OK")]
    [InlineData("HTTP/1.1 200 OK\r\n folded: continuation")]
    [InlineData("HTTP/1.1 200 OK\r\nNoColon")]
    [InlineData("HTTP/1.1 200 OK\r\nSpace : before colon")]
    public void MalformedResponseHeadIsRejected(string head)
    {
        Assert.Throws<HttpIOException>(() => Http1ResponseHead.Parse(Encoding.Latin1.GetBytes(head)));
    }

    [Fact]
    public async Task HeadSplitAcrossReadsIsReassembledAndLeftoverServed()
    {
        var bytes = "HTTP/1.1 200 OK\r\nA: 1\r\n\r\nbody"u8.ToArray();
        await using var stream = new HttpReadStream(new TrickleStream(bytes, chunk: 3));

        var head = await stream.ReadResponseHeadAsync(TestContext.Current.CancellationToken);
        using var rest = new MemoryStream();
        await stream.CopyToAsync(rest, TestContext.Current.CancellationToken);

        Assert.Equal("1", head.GetValue("A"));
        Assert.Equal("body", Encoding.ASCII.GetString(rest.ToArray()));
    }

    [Fact]
    public async Task OversizedHeadIsRejected()
    {
        var bytes = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nX: " + new string('a', 70_000));
        await using var stream = new HttpReadStream(new MemoryStream(bytes));

        await Assert.ThrowsAsync<HttpIOException>(() => stream.ReadResponseHeadAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>Returns at most <c>chunk</c> bytes per read, like a slow network.</summary>
    private sealed class TrickleStream(byte[] data, int chunk) : MemoryStream(data)
    {
        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(chunk, buffer.Length)]);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            base.ReadAsync(buffer[..Math.Min(chunk, buffer.Length)], cancellationToken);
    }
}
