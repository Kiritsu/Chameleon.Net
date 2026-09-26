using System.Text;
using Chameleon.Net.Http.Http2.Hpack;

namespace Chameleon.Net.Tests.Http;

/// <summary>Vectors from RFC 7541 Appendix C.</summary>
public sealed class HpackTests
{
    private static readonly KeyValuePair<string, string>[][] Requests =
    [
        [new(":method", "GET"), new(":scheme", "http"), new(":path", "/"), new(":authority", "www.example.com")],
        [new(":method", "GET"), new(":scheme", "http"), new(":path", "/"), new(":authority", "www.example.com"), new("cache-control", "no-cache")],
        [new(":method", "GET"), new(":scheme", "https"), new(":path", "/index.html"), new(":authority", "www.example.com"), new("custom-key", "custom-value")],
    ];

    private static readonly string[] PlainBlocks =
    [
        "828684410f7777772e6578616d706c652e636f6d",
        "828684be58086e6f2d6361636865",
        "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
    ];

    private static readonly string[] HuffmanBlocks =
    [
        "828684418cf1e3c2e5f23a6ba0ab90f4ff",
        "828684be5886a8eb10649cbf",
        "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
    ];

    [Theory]
    [InlineData(10, 5, "0a")]
    [InlineData(1337, 5, "1f9a0a")]
    [InlineData(42, 8, "2a")]
    public void IntegersRoundTrip(int value, int prefixBits, string hex)
    {
        var encoded = new List<byte>();
        HpackInteger.Write(encoded, value, prefixBits, 0);
        var offset = 0;

        Assert.Equal(hex, Convert.ToHexStringLower([.. encoded]));
        Assert.Equal(value, HpackInteger.Read(Convert.FromHexString(hex), ref offset, prefixBits));
    }

    [Theory]
    [InlineData("www.example.com", "f1e3c2e5f23a6ba0ab90f4ff")]
    [InlineData("no-cache", "a8eb10649cbf")]
    [InlineData("custom-key", "25a849e95ba97d7f")]
    [InlineData("custom-value", "25a849e95bb8e8b4bf")]
    public void HuffmanMatchesRfc(string text, string hex)
    {
        var raw = Encoding.ASCII.GetBytes(text);
        var encoded = new byte[Huffman.EncodedLength(raw)];
        Huffman.Encode(raw, encoded);

        Assert.Equal(hex, Convert.ToHexStringLower(encoded));
        Assert.Equal(text, Encoding.ASCII.GetString(Huffman.Decode(Convert.FromHexString(hex))));
    }

    [Fact]
    public void HuffmanRoundTripsEveryOctet()
    {
        var all = Enumerable.Range(0, 256).Select(static b => (byte)b).ToArray();
        var encoded = new byte[Huffman.EncodedLength(all)];
        Huffman.Encode(all, encoded);

        Assert.Equal(all, Huffman.Decode(encoded));
    }

    [Theory]
    [InlineData("f1e3c2e5f23a6ba0ab90f400")] // padding not all ones
    [InlineData("f1e3c2e5f23a6ba0ab90f4ffff")] // padding longer than 7 bits
    public void InvalidHuffmanPaddingIsRejected(string hex)
    {
        Assert.Throws<HpackException>(() => Huffman.Decode(Convert.FromHexString(hex)));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DecoderFollowsRfcRequestSequence(bool huffman)
    {
        var decoder = new HpackDecoder(4096);
        var blocks = huffman ? HuffmanBlocks : PlainBlocks;

        for (var i = 0; i < blocks.Length; i++)
        {
            Assert.Equal(Requests[i], decoder.Decode(Convert.FromHexString(blocks[i])));
        }
    }

    [Fact]
    public void EncoderReproducesRfcHuffmanSequence()
    {
        var encoder = new HpackEncoder();

        for (var i = 0; i < Requests.Length; i++)
        {
            Assert.Equal(HuffmanBlocks[i], Convert.ToHexStringLower(encoder.Encode(Requests[i])));
        }
    }

    [Fact]
    public void EncoderAndDecoderStayInSyncAcrossBlocks()
    {
        var encoder = new HpackEncoder();
        var decoder = new HpackDecoder(4096);
        KeyValuePair<string, string>[] headers =
        [
            new(":method", "POST"), new(":path", "/api/v1/items?x=1"), new(":authority", "api.example.com"), new(":scheme", "https"),
            new("content-type", "application/json; charset=utf-8"), new("user-agent", "okhttp/4.12.0"), new("x-custom", "éÿ"),
        ];

        for (var round = 0; round < 5; round++)
        {
            Assert.Equal(headers, decoder.Decode(encoder.Encode(headers)));
        }
    }

    [Theory]
    [InlineData("80")] // index 0
    [InlineData("be")] // dynamic index on an empty table
    [InlineData("4005")] // truncated name literal
    [InlineData("823fe11f")] // size update after a header
    public void MalformedBlocksAreRejected(string hex)
    {
        Assert.Throws<HpackException>(() => new HpackDecoder(4096).Decode(Convert.FromHexString(hex)));
    }
}
