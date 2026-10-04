using System.Text.Json;
using Chameleon.Net.Http.Http2.Hpack;
using Chameleon.Net.Inspector.Analysis;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Tests.Inspector;

/// <summary>Header blocks real browsers sent on one HTTP/2 connection (Captures/*.hpack.jsonl, from the inspector's reports), replayed
/// through each set of HPACK rules: the browser's must reproduce every field, the other must not.</summary>
public sealed class HpackCaptureTests
{
    [Theory]
    [InlineData("edge-154-windows", HpackIndexing.OkHttp)]
    [InlineData("safari-26-macos", HpackIndexing.Nghttp2)]
    public void TheBrowsersRulesReproduceItsHeaderBlocks(string capture, HpackIndexing rules)
    {
        var requests = Load(capture);

        // The captures leave out the /favicon.ico request the browser sent on the same connection: its entries shift dynamic indices.
        Assert.All(HpackReplayer.Compare(requests, tls: true, rules, anyDynamicIndex: true), static differences => Assert.Empty(differences));
        var other = rules == HpackIndexing.OkHttp ? HpackIndexing.Nghttp2 : HpackIndexing.OkHttp;
        Assert.Contains(HpackReplayer.Compare(requests, tls: true, other, anyDynamicIndex: true), static differences => differences.Count > 0);
    }

    [Theory]
    [InlineData("edge-154-windows")]
    [InlineData("safari-26-macos")]
    public void BothBrowsersSendOneFieldPerCookie(string capture)
    {
        var withCookies = Load(capture).Where(static r => r.Header("cookie") is not null).ToList();

        Assert.NotEmpty(withCookies);
        Assert.All(withCookies, static r => Assert.Equal(2, r.Headers.Count(static h => h.Name == "cookie")));
    }

    [Fact]
    public void ReplayFollowsTheTableSizeTheClientChose()
    {
        var client = new Client(HpackIndexing.Nghttp2);
        client.Encoder.SetMaxTableSize(0);
        var replayer = new HpackReplayer(HpackIndexing.Nghttp2);

        // Without a table, :authority is a literal on every request; a replay keeping 4096 bytes would expect it indexed the second time.
        Assert.Empty(replayer.Next(Request("/a"), client.Send(Request("/a"))));
        Assert.Empty(replayer.Next(Request("/b"), client.Send(Request("/b"))));
    }

    [Theory]
    [InlineData(HpackIndexing.OkHttp)]
    [InlineData(HpackIndexing.Nghttp2)]
    public void ReplayEvictsLikeTheClientWhenTheTableOverflows(HpackIndexing rules)
    {
        var client = new Client(rules);
        var replayer = new HpackReplayer(rules);

        // 40 distinct 300-byte values: ten times the table, so entries are evicted throughout, and the first ones are sent again
        // once they've left the table.
        for (var request = 0; request < 50; request++)
        {
            KeyValuePair<string, string>[] fields = [.. Request("/"), new("x-token", new string((char)('a' + request % 40 % 26), 300 + request % 40))];
            Assert.Empty(replayer.Next(fields, client.Send(fields)));
        }
    }

    [Fact]
    public void ReplayCountsBlocksThatAreNotRequests()
    {
        var client = new Client(HpackIndexing.OkHttp);
        var replayer = new HpackReplayer(HpackIndexing.OkHttp);
        var skipping = new HpackReplayer(HpackIndexing.OkHttp);
        KeyValuePair<string, string>[] trailers = [new("x-checksum", "abc")];

        var first = client.Send(Request("/a"));
        Assert.Empty(replayer.Next(Request("/a"), first));
        Assert.Empty(skipping.Next(Request("/a"), first));
        Assert.Empty(replayer.Next(trailers, client.Send(trailers)));
        var second = client.Send(Request("/b"));

        // The trailer's entry shifts every later dynamic index: a replay that never saw it expects other indices.
        Assert.Empty(replayer.Next(Request("/b"), second));
        Assert.NotEmpty(skipping.Next(Request("/b"), second));
    }

    [Fact]
    public void BuiltInProfilesUseTheRulesTheirBrowserWasSeenWith()
    {
        Assert.Equal(new HpackProfile(SplitCookies: true), BuiltInProfiles.Edge154Windows.Http2.Hpack);
        Assert.Equal(new HpackProfile(SplitCookies: true, HpackIndexing.Nghttp2), BuiltInProfiles.Safari26MacOS.Http2.Hpack);
    }

    private static KeyValuePair<string, string>[] Request(string path) =>
        [new(":method", "GET"), new(":authority", "example.com"), new(":scheme", "https"), new(":path", path), new("user-agent", "test")];

    /// <summary>A client's encoder and, as on the inspector's side of the connection, one decoder reporting each block's representations.</summary>
    private sealed class Client(HpackIndexing rules)
    {
        private readonly HpackDecoder _decoder = new(4096);

        public HpackEncoder Encoder { get; } = new(rules);

        public List<HpackFieldTrace> Send(KeyValuePair<string, string>[] fields)
        {
            var trace = new List<HpackFieldTrace>();
            _decoder.Decode(Encoder.Encode(fields), trace);
            return trace;
        }
    }

    private static List<RequestCapture> Load(string capture) =>
        [.. File.ReadLines(Path.Combine(AppContext.BaseDirectory, "Inspector", "Captures", $"{capture}.hpack.jsonl"))
            .Where(static line => line.Length > 0)
            .Select(static line => JsonSerializer.Deserialize<CapturedRequest>(line, ReportJson.Options)!)
            .Select(static r => new RequestCapture("2", r.Method, r.Path, r.Authority, r.Headers, [], WebSocket: false, Hpack: r.Hpack))];

    private sealed record CapturedRequest(string Method, string Path, string? Authority, IReadOnlyList<HeaderField> Headers, IReadOnlyList<HpackFieldReport> Hpack);
}
