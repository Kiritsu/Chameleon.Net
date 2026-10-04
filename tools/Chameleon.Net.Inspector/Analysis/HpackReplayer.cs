using Chameleon.Net.Http.Http2.Hpack;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Analysis;

/// <param name="Name">The field's name.</param>
/// <param name="Actual">How the client encoded it.</param>
/// <param name="Expected">How the encoder under test encodes it.</param>
internal sealed record HpackDifference(string Name, string Actual, string Expected);

/// <summary>Re-encodes one connection's header blocks, fed in the order the client sent them (trailers included), with an encoder following
/// the given rules, and compares each field's representation with the client's. Its dynamic table evolves as the client's did, so every
/// block can be checked, each one processed once.</summary>
/// <param name="anyDynamicIndex">Don't compare which dynamic table entry is referenced, only that one is: for header blocks recorded
/// without some that preceded them on the connection (such as an unreported /favicon.ico), whose entries shift the indices.</param>
internal sealed class HpackReplayer(HpackIndexing rules, bool anyDynamicIndex = false)
{
    /// <summary>The inspector doesn't send SETTINGS_HEADER_TABLE_SIZE, so clients encode against the default table, and size updates
    /// can't exceed it.</summary>
    public const int TableSize = 4096;

    private readonly HpackEncoder _encoder = new(rules);

    // Sized like the encoder's table, so it evicts as the encoder does instead of keeping every field the connection sent.
    private readonly HpackDecoder _decoder = new(TableSize);

    /// <param name="fields">The block's fields, in wire order.</param>
    /// <param name="observed">How the client represented them, size updates included.</param>
    /// <returns>The fields encoded differently; empty when the rules reproduce the client.</returns>
    public List<HpackDifference> Next(IReadOnlyList<KeyValuePair<string, string>> fields, IReadOnlyList<HpackFieldTrace> observed)
    {
        // The client chose its table size; the comparison is about what it then did with it.
        foreach (var update in observed.Where(static t => t.Representation == HpackRepresentation.SizeUpdate))
        {
            _encoder.SetMaxTableSize(update.Index);
        }

        var trace = new List<HpackFieldTrace>();
        _decoder.Decode(_encoder.Encode(fields), trace);

        return [.. observed.Where(static t => t.Representation != HpackRepresentation.SizeUpdate)
            .Zip(trace.Where(static t => t.Representation != HpackRepresentation.SizeUpdate), fields)
            .Select(field => new HpackDifference(field.Third.Key, Describe(field.First), Describe(field.Second)))
            .Where(static difference => difference.Actual != difference.Expected)];
    }

    /// <summary>Replays header blocks recorded in inspection reports: fields rebuilt from each request's line and headers.</summary>
    /// <returns>Per request, the fields encoded differently.</returns>
    public static List<List<HpackDifference>> Compare(IReadOnlyList<RequestCapture> requests, bool tls, HpackIndexing rules, bool anyDynamicIndex = false)
    {
        var replayer = new HpackReplayer(rules, anyDynamicIndex);
        return [.. requests.Select(request =>
        {
            var observed = request.Hpack ?? [];
            return replayer.Next(Fields(request, observed, tls),
                [.. observed.Select(static f => new HpackFieldTrace(f.Representation, f.Index ?? 0, f.NameHuffman, f.Huffman))]);
        })];
    }

    private static List<KeyValuePair<string, string>> Fields(RequestCapture request, IReadOnlyList<HpackFieldReport> observed, bool tls)
    {
        using var regular = request.Headers.GetEnumerator();
        return [.. observed.Where(static f => f.Representation != HpackRepresentation.SizeUpdate).Select(field => new KeyValuePair<string, string>(field.Name!, field.Name switch
        {
            ":method" => request.Method,
            ":path" => request.Path,
            ":authority" => request.Authority ?? "",
            ":scheme" => tls ? "https" : "http",
            _ => regular.MoveNext() ? regular.Current.Value : "",
        }))];
    }

    private string Describe(HpackFieldTrace field)
    {
        var index = anyDynamicIndex && field.Index > HpackStaticTable.Count ? HpackStaticTable.Count + 1 : field.Index;
        var table = index > HpackStaticTable.Count ? " (dynamic)" : "";
        return field.Representation == HpackRepresentation.Indexed
            ? $"indexed {index}{table}"
            : $"{field.Representation} literal with {(index == 0 ? $"a new {(field.NameHuffman ? "Huffman" : "raw")} name" : $"name {index}{table}")} and a {(field.ValueHuffman ? "Huffman" : "raw")} value";
    }
}
