namespace Chameleon.Net.Http.Http2.Hpack;

/// <summary>How a header block field was represented on the wire (RFC 7541 §6).</summary>
internal enum HpackRepresentation
{
    Indexed,
    IncrementalIndexing,
    WithoutIndexing,
    NeverIndexed,
    SizeUpdate,
}

/// <param name="Index">Indexed: the entry. Literals: the name's index, 0 for a new name. Size updates: the new size.</param>
/// <param name="NameHuffman">Literal with a new name: whether the name was Huffman-coded.</param>
/// <param name="ValueHuffman">Literals: whether the value was Huffman-coded.</param>
internal readonly record struct HpackFieldTrace(HpackRepresentation Representation, int Index, bool NameHuffman = false, bool ValueHuffman = false);
