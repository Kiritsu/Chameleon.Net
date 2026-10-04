using System.Text;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Http.Http2.Hpack;

/// <summary>Encodes header blocks the way the profiled client does, since the representation is visible to the server. Strings are
/// Huffman-coded when that is shorter under every policy; which fields are indexed, and how, depends on <see cref="HpackIndexing"/>.</summary>
internal sealed class HpackEncoder(HpackIndexing indexing = HpackIndexing.OkHttp)
{
    private const int DefaultTableSize = 4096;

    /// <summary>nghttp2 doesn't index these (<c>hd_deflate_should_indexing</c>): values that change on every request or response.</summary>
    private static readonly HashSet<string> Nghttp2Unindexed =
        [":path", "age", "content-length", "etag", "if-modified-since", "if-none-match", "location", "set-cookie"];

    private readonly HpackDynamicTable _table = new(DefaultTableSize);
    private bool _emitSizeUpdate;
    private int _smallestSizeSinceLastBlock = int.MaxValue;

    /// <summary>The largest table the encoder uses, whatever the peer allows: OkHttp's SETTINGS_HEADER_TABLE_SIZE_LIMIT, nghttp2's
    /// default deflate buffer.</summary>
    private int TableSizeLimit => indexing == HpackIndexing.Nghttp2 ? 4096 : 16384;

    /// <summary>Applies the peer's SETTINGS_HEADER_TABLE_SIZE like OkHttp's <c>resizeHeaderTable</c> and nghttp2's
    /// <c>nghttp2_hd_deflate_change_table_size</c>: announced at the start of the next block, preceded by the smallest intermediate size
    /// when the table shrank in between.</summary>
    public void SetMaxTableSize(int peerMaxTableSize)
    {
        var size = Math.Min(peerMaxTableSize, TableSizeLimit);
        if (size == _table.MaxSize)
        {
            return;
        }

        if (size < _table.MaxSize)
        {
            _smallestSizeSinceLastBlock = Math.Min(_smallestSizeSinceLastBlock, size);
        }

        _emitSizeUpdate = true;
        _table.Resize(size);
    }

    public byte[] Encode(IEnumerable<KeyValuePair<string, string>> headers)
    {
        var block = new List<byte>();
        if (_emitSizeUpdate)
        {
            if (_smallestSizeSinceLastBlock < _table.MaxSize)
            {
                HpackInteger.Write(block, _smallestSizeSinceLastBlock, 5, 0x20);
            }

            HpackInteger.Write(block, _table.MaxSize, 5, 0x20);
            _emitSizeUpdate = false;
            _smallestSizeSinceLastBlock = int.MaxValue;
        }

        foreach (var (name, value) in headers)
        {
            if (indexing == HpackIndexing.Nghttp2)
            {
                EncodeNghttp2(block, name, value);
            }
            else
            {
                EncodeOkHttp(block, name, value);
            }
        }

        return [.. block];
    }

    /// <summary>OkHttp's <c>Hpack.Writer</c>, which Chrome matches too: full matches are indexed (static lookups limited to :method,
    /// :path and :scheme); pseudo-headers other than :authority are literals without indexing; everything else is a literal with
    /// incremental indexing.</summary>
    private void EncodeOkHttp(List<byte> block, string name, string value)
    {
        var exact = FirstStaticPseudoIndex(name, value);
        if (exact == 0)
        {
            exact = DynamicIndex(_table.IndexOf(name, value));
        }

        if (exact > 0)
        {
            HpackInteger.Write(block, exact, 7, 0x80);
            return;
        }

        var nameIndex = NameIndex(name);
        if (name.StartsWith(':') && name != ":authority" && nameIndex > 0)
        {
            WriteLiteral(block, nameIndex, 4, 0x00, name, value);
        }
        else
        {
            WriteLiteral(block, nameIndex, 6, 0x40, name, value);
            _table.Add(name, value);
        }
    }

    /// <summary>nghttp2's <c>deflate_nv</c>, which Safari's encoder matches: authorization and cookies shorter than 20 bytes are never
    /// indexed; any full match, static or dynamic, is indexed; the fields in <see cref="Nghttp2Unindexed"/>, and those taking more than
    /// three quarters of the table, are literals without indexing; everything else is a literal with incremental indexing.</summary>
    private void EncodeNghttp2(List<byte> block, string name, string value)
    {
        var neverIndexed = name == "authorization" || (name == "cookie" && value.Length < 20);
        if (!neverIndexed)
        {
            var exact = HpackStaticTable.IndexOf(name, value);
            if (exact == 0)
            {
                exact = DynamicIndex(_table.IndexOf(name, value));
            }

            if (exact > 0)
            {
                HpackInteger.Write(block, exact, 7, 0x80);
                return;
            }
        }

        var nameIndex = NameIndex(name);
        if (neverIndexed)
        {
            WriteLiteral(block, nameIndex, 4, 0x10, name, value);
        }
        else if (Nghttp2Unindexed.Contains(name) || name.Length + value.Length + HpackDynamicTable.EntryOverhead > _table.MaxSize * 3 / 4)
        {
            WriteLiteral(block, nameIndex, 4, 0x00, name, value);
        }
        else
        {
            WriteLiteral(block, nameIndex, 6, 0x40, name, value);
            _table.Add(name, value);
        }
    }

    /// <summary>Static entries 2..7 are the only ones OkHttp matches with their values (:method, :path, :scheme).</summary>
    private static int FirstStaticPseudoIndex(string name, string value)
    {
        for (var index = 2; index <= 7; index++)
        {
            var entry = HpackStaticTable.Entries[index - 1];
            if (entry.Key == name && entry.Value == value)
            {
                return index;
            }
        }

        return 0;
    }

    private static int DynamicIndex(int dynamicIndex) => dynamicIndex < 0 ? 0 : HpackStaticTable.Count + 1 + dynamicIndex;

    private int NameIndex(string name)
    {
        var staticIndex = HpackStaticTable.IndexOfName(name);
        return staticIndex > 0 ? staticIndex : DynamicIndex(_table.IndexOfName(name));
    }

    private static void WriteLiteral(List<byte> block, int nameIndex, int prefixBits, byte pattern, string name, string value)
    {
        HpackInteger.Write(block, nameIndex, prefixBits, pattern);
        if (nameIndex == 0)
        {
            WriteString(block, name);
        }

        WriteString(block, value);
    }

    private static void WriteString(List<byte> block, string value)
    {
        var raw = Encoding.Latin1.GetBytes(value);
        var huffmanLength = Huffman.EncodedLength(raw);
        if (huffmanLength < raw.Length)
        {
            var encoded = new byte[huffmanLength];
            Huffman.Encode(raw, encoded);
            HpackInteger.Write(block, encoded.Length, 7, 0x80);
            block.AddRange(encoded);
        }
        else
        {
            HpackInteger.Write(block, raw.Length, 7, 0x00);
            block.AddRange(raw);
        }
    }
}
