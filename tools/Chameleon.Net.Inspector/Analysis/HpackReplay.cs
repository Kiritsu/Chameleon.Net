using Chameleon.Net.Http.Http2.Hpack;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Analysis;

/// <param name="Name">The field's name.</param>
/// <param name="Actual">How the client encoded it.</param>
/// <param name="Expected">How the encoder under test encodes it.</param>
internal sealed record HpackDifference(string Name, string Actual, string Expected);

/// <summary>Re-encodes a connection's header blocks, in the order the client sent them, with an encoder following the given rules, and
/// compares each field's representation with what the client sent. The dynamic table then evolves as the client's did, so every
/// request can be checked, not only the first.</summary>
internal static class HpackReplay
{
    /// <param name="anyDynamicIndex">Don't compare which dynamic table entry is referenced, only that one is: for header blocks recorded
    /// without some that preceded them on the connection (such as an unreported /favicon.ico), whose entries shift the indices.</param>
    /// <returns>Per request, the fields encoded differently; empty lists when the rules reproduce the client.</returns>
    public static List<List<HpackDifference>> Compare(IReadOnlyList<RequestCapture> requests, bool tls, HpackIndexing indexing, bool anyDynamicIndex = false)
    {
        string Describe(HpackRepresentation representation, int index, bool valueHuffman, bool nameHuffman) =>
            HpackReplay.Describe(representation, anyDynamicIndex && index > HpackStaticTable.Count ? HpackStaticTable.Count + 1 : index, valueHuffman, nameHuffman);

        var encoder = new HpackEncoder(indexing);
        var decoder = new HpackDecoder(int.MaxValue);
        var result = new List<List<HpackDifference>>(requests.Count);
        foreach (var request in requests)
        {
            var observed = request.Hpack?.Where(static f => f.Representation != HpackRepresentation.SizeUpdate).ToList() ?? [];
            var trace = new List<HpackFieldTrace>();
            decoder.Decode(encoder.Encode(Fields(request, observed, tls)), trace);
            var expected = trace.Where(static t => t.Representation != HpackRepresentation.SizeUpdate).ToList();

            result.Add([.. observed.Zip(expected)
                .Select(pair => new HpackDifference(
                    pair.First.Name!,
                    Describe(pair.First.Representation, pair.First.Index ?? 0, pair.First.Huffman, pair.First.NameHuffman),
                    Describe(pair.Second.Representation, pair.Second.Index, pair.Second.ValueHuffman, pair.Second.NameHuffman)))
                .Where(static difference => difference.Actual != difference.Expected)]);
        }

        return result;
    }

    /// <summary>The header block's fields in wire order: pseudo-headers from the request line, regular ones in the order received.</summary>
    private static List<KeyValuePair<string, string>> Fields(RequestCapture request, List<HpackFieldReport> observed, bool tls)
    {
        using var regular = request.Headers.GetEnumerator();
        var fields = new List<KeyValuePair<string, string>>(observed.Count);
        foreach (var field in observed)
        {
            var value = field.Name switch
            {
                ":method" => request.Method,
                ":path" => request.Path,
                ":authority" => request.Authority ?? "",
                ":scheme" => tls ? "https" : "http",
                _ => regular.MoveNext() ? regular.Current.Value : "",
            };
            fields.Add(new(field.Name!, value));
        }

        return fields;
    }

    private static string Describe(HpackRepresentation representation, int index, bool valueHuffman, bool nameHuffman) =>
        representation == HpackRepresentation.Indexed
            ? index > HpackStaticTable.Count ? $"indexed {index} (dynamic)" : $"indexed {index}"
            : $"{representation} literal with {(index == 0 ? $"a new {(nameHuffman ? "Huffman" : "raw")} name" : $"name {index}")} and a {(valueHuffman ? "Huffman" : "raw")} value";
}
