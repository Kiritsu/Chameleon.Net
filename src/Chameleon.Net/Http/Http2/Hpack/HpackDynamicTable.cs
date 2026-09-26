namespace Chameleon.Net.Http.Http2.Hpack;

/// <summary>RFC 7541 §4. Index 0 is the newest entry. Names and values are Latin-1 strings, so string length equals octet length.</summary>
internal sealed class HpackDynamicTable(int maxSize)
{
    private const int EntryOverhead = 32;

    private readonly List<KeyValuePair<string, string>> _entries = [];
    private int _size;

    public int MaxSize { get; private set; } = maxSize;

    public int Count => _entries.Count;

    public KeyValuePair<string, string> this[int index] => _entries[index];

    public void Add(string name, string value)
    {
        var entrySize = name.Length + value.Length + EntryOverhead;
        if (entrySize > MaxSize)
        {
            _entries.Clear();
            _size = 0;
            return;
        }

        EvictUntilFits(MaxSize - entrySize);
        _entries.Insert(0, new(name, value));
        _size += entrySize;
    }

    public void Resize(int maxSize)
    {
        MaxSize = maxSize;
        EvictUntilFits(maxSize);
    }

    /// <returns>0-based dynamic index of an exact match, or -1.</returns>
    public int IndexOf(string name, string value) =>
        _entries.FindIndex(entry => string.Equals(entry.Key, name, StringComparison.Ordinal) && string.Equals(entry.Value, value, StringComparison.Ordinal));

    /// <returns>0-based dynamic index of a name match, or -1.</returns>
    public int IndexOfName(string name) => _entries.FindIndex(entry => string.Equals(entry.Key, name, StringComparison.Ordinal));

    private void EvictUntilFits(int budget)
    {
        while (_size > budget && _entries.Count > 0)
        {
            var oldest = _entries[^1];
            _size -= oldest.Key.Length + oldest.Value.Length + EntryOverhead;
            _entries.RemoveAt(_entries.Count - 1);
        }
    }
}
