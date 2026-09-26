namespace Chameleon.Net.Http.Http2.Hpack;

/// <summary>RFC 7541 §5.2 canonical Huffman code. Table data lives in Huffman.Table.cs, extracted from the .NET runtime's implementation.</summary>
internal static partial class Huffman
{
    private const int EndOfString = 256;

    /// <summary>Binary trie: node <c>n</c>'s children are at <c>[2n]</c> (bit 0) and <c>[2n + 1]</c> (bit 1).
    /// Positive values are child nodes, negative values are <c>~symbol</c>, 0 means no code.</summary>
    private static readonly int[] Trie = BuildTrie();

    public static int EncodedLength(ReadOnlySpan<byte> value)
    {
        var bits = 0L;
        foreach (var symbol in value)
        {
            bits += BitLengths[symbol];
        }

        return (int)((bits + 7) / 8);
    }

    /// <param name="destination">Exactly <see cref="EncodedLength"/> bytes.</param>
    public static void Encode(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        var buffer = 0UL;
        var pending = 0;
        var offset = 0;
        foreach (var symbol in value)
        {
            buffer = (buffer << BitLengths[symbol]) | Codes[symbol];
            pending += BitLengths[symbol];
            while (pending >= 8)
            {
                pending -= 8;
                destination[offset++] = (byte)(buffer >> pending);
            }
        }

        if (pending > 0)
        {
            // Pad with the most significant bits of EOS, i.e. ones.
            destination[offset] = (byte)((buffer << (8 - pending)) | (0xFFu >> pending));
        }
    }

    /// <exception cref="HpackException">Invalid code, EOS inside the string, or padding longer than 7 bits / not all ones.</exception>
    public static byte[] Decode(ReadOnlySpan<byte> encoded)
    {
        var output = new List<byte>(encoded.Length * 8 / 5);
        var node = 0;
        var bitsSinceSymbol = 0;
        var paddingIsOnes = true;

        foreach (var octet in encoded)
        {
            for (var shift = 7; shift >= 0; shift--)
            {
                var bit = (octet >> shift) & 1;
                var next = Trie[(node * 2) + bit];
                if (next == 0)
                {
                    throw new HpackException("Invalid Huffman code.");
                }

                bitsSinceSymbol++;
                paddingIsOnes &= bit == 1;

                if (next > 0)
                {
                    node = next;
                    continue;
                }

                var symbol = ~next;
                if (symbol == EndOfString)
                {
                    throw new HpackException("EOS symbol inside a Huffman-encoded string.");
                }

                output.Add((byte)symbol);
                node = 0;
                bitsSinceSymbol = 0;
                paddingIsOnes = true;
            }
        }

        if (bitsSinceSymbol > 7 || !paddingIsOnes)
        {
            throw new HpackException("Invalid Huffman padding.");
        }

        return [.. output];
    }

    private static int[] BuildTrie()
    {
        var trie = new int[2 * 512];
        var nodes = 1;
        for (var symbol = 0; symbol <= EndOfString; symbol++)
        {
            var code = Codes[symbol];
            var length = BitLengths[symbol];
            var node = 0;
            for (var bit = length - 1; bit > 0; bit--)
            {
                var slot = (node * 2) + (int)((code >> bit) & 1);
                if (trie[slot] == 0)
                {
                    trie[slot] = nodes++;
                }

                node = trie[slot];
            }

            trie[(node * 2) + (int)(code & 1)] = ~symbol;
        }

        return trie;
    }
}
