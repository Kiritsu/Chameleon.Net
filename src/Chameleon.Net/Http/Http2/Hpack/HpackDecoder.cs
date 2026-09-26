using System.Text;

namespace Chameleon.Net.Http.Http2.Hpack;

internal sealed class HpackDecoder(int maxTableSize)
{
    /// <summary>Guards memory against a hostile header block (sum of name + value lengths).</summary>
    private const int MaxHeaderListSize = 1024 * 1024;

    private readonly HpackDynamicTable _table = new(maxTableSize);

    /// <param name="block">A complete header block (HEADERS/PUSH_PROMISE payload plus all CONTINUATIONs).</param>
    /// <exception cref="HpackException">The block is malformed; the connection must be closed.</exception>
    public List<KeyValuePair<string, string>> Decode(ReadOnlySpan<byte> block)
    {
        var headers = new List<KeyValuePair<string, string>>();
        var listSize = 0;
        var offset = 0;

        while (offset < block.Length)
        {
            var first = block[offset];
            KeyValuePair<string, string> header;

            if ((first & 0x80) != 0)
            {
                header = Lookup(HpackInteger.Read(block, ref offset, 7));
            }
            else if ((first & 0xC0) == 0x40)
            {
                header = ReadLiteral(block, ref offset, 6);
                _table.Add(header.Key, header.Value);
            }
            else if ((first & 0xE0) == 0x20)
            {
                if (headers.Count > 0)
                {
                    throw new HpackException("Dynamic table size update after the first header field.");
                }

                var size = HpackInteger.Read(block, ref offset, 5);
                if (size > maxTableSize)
                {
                    throw new HpackException($"Dynamic table size update to {size} exceeds the advertised {maxTableSize}.");
                }

                _table.Resize(size);
                continue;
            }
            else
            {
                // Literal without indexing (0000) or never indexed (0001).
                header = ReadLiteral(block, ref offset, 4);
            }

            listSize += header.Key.Length + header.Value.Length;
            if (listSize > MaxHeaderListSize)
            {
                throw new HpackException("Header list exceeds 1 MiB.");
            }

            headers.Add(header);
        }

        return headers;
    }

    private KeyValuePair<string, string> ReadLiteral(ReadOnlySpan<byte> block, ref int offset, int prefixBits)
    {
        var nameIndex = HpackInteger.Read(block, ref offset, prefixBits);
        var name = nameIndex == 0 ? ReadString(block, ref offset) : Lookup(nameIndex).Key;
        return new(name, ReadString(block, ref offset));
    }

    private static string ReadString(ReadOnlySpan<byte> block, ref int offset)
    {
        if (offset >= block.Length)
        {
            throw new HpackException("Truncated string literal.");
        }

        var huffman = (block[offset] & 0x80) != 0;
        var length = HpackInteger.Read(block, ref offset, 7);
        if (length > block.Length - offset)
        {
            throw new HpackException("String literal runs past the header block.");
        }

        var raw = block.Slice(offset, length);
        offset += length;
        return Encoding.Latin1.GetString(huffman ? Huffman.Decode(raw) : raw);
    }

    private KeyValuePair<string, string> Lookup(int index)
    {
        if (index == 0)
        {
            throw new HpackException("Index 0 is not valid.");
        }

        if (index <= HpackStaticTable.Count)
        {
            return HpackStaticTable.Entries[index - 1];
        }

        var dynamicIndex = index - HpackStaticTable.Count - 1;
        return dynamicIndex < _table.Count ? _table[dynamicIndex] : throw new HpackException($"Index {index} is out of range.");
    }
}
