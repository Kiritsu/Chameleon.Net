using System.Text;

namespace Chameleon.Net.Http.Http2.Hpack;

/// <summary>Encodes header blocks the way OkHttp's <c>Hpack.Writer</c> does, since the representation is visible to the server:
/// full matches are indexed (static lookups limited to :method, :path and :scheme); pseudo-headers other than :authority are
/// literals without indexing; everything else is a literal with incremental indexing; strings are Huffman-coded when that is shorter.</summary>
internal sealed class HpackEncoder
{
    private const int DefaultTableSize = 4096;

    /// <summary>OkHttp's SETTINGS_HEADER_TABLE_SIZE_LIMIT: larger peer settings are honoured only up to this size.</summary>
    private const int TableSizeLimit = 16384;

    private readonly HpackDynamicTable _table = new(DefaultTableSize);
    private bool _emitSizeUpdate;
    private int _smallestSizeSinceLastBlock = int.MaxValue;

    /// <summary>Applies the peer's SETTINGS_HEADER_TABLE_SIZE like OkHttp's <c>resizeHeaderTable</c>: announced at the start of the next block,
    /// preceded by the smallest intermediate size when the table shrank in between.</summary>
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
            var exact = ExactIndex(name, value);
            if (exact > 0)
            {
                HpackInteger.Write(block, exact, 7, 0x80);
                continue;
            }

            var nameIndex = NameIndex(name);
            if (nameIndex == 0)
            {
                block.Add(0x40);
                WriteString(block, name);
                WriteString(block, value);
                _table.Add(name, value);
            }
            else if (name.StartsWith(':') && name != ":authority")
            {
                HpackInteger.Write(block, nameIndex, 4, 0x00);
                WriteString(block, value);
            }
            else
            {
                HpackInteger.Write(block, nameIndex, 6, 0x40);
                WriteString(block, value);
                _table.Add(name, value);
            }
        }

        return [.. block];
    }

    private int ExactIndex(string name, string value)
    {
        // Static entries 2..7 are the only ones with values worth matching (:method, :path, :scheme).
        for (var index = 2; index <= 7; index++)
        {
            var entry = HpackStaticTable.Entries[index - 1];
            if (entry.Key == name && entry.Value == value)
            {
                return index;
            }
        }

        var dynamicIndex = _table.IndexOf(name, value);
        return dynamicIndex < 0 ? 0 : HpackStaticTable.Count + 1 + dynamicIndex;
    }

    private int NameIndex(string name)
    {
        var staticIndex = HpackStaticTable.IndexOfName(name);
        if (staticIndex > 0)
        {
            return staticIndex;
        }

        var dynamicIndex = _table.IndexOfName(name);
        return dynamicIndex < 0 ? 0 : HpackStaticTable.Count + 1 + dynamicIndex;
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
