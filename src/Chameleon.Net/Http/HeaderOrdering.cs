using System.Globalization;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Http;

internal static class HeaderOrdering
{
    /// <summary>Headers absent from <paramref name="order"/> come first, in their original order (OkHttp appends its own headers after the app's);
    /// listed headers follow in profile order. Under <see cref="HeaderCasing.AsSpecified"/> listed names take the profile's spelling.</summary>
    public static List<KeyValuePair<string, string>> Order(
        IEnumerable<KeyValuePair<string, string>> headers, IReadOnlyList<string> order, HeaderCasing casing)
    {
        var unlisted = new List<KeyValuePair<string, string>>();
        var listed = new List<(int Rank, KeyValuePair<string, string> Header)>();

        foreach (var (name, value) in headers)
        {
            var rank = IndexOf(order, name);
            if (rank < 0)
            {
                unlisted.Add(new(ApplyCasing(name, name, casing), value));
            }
            else
            {
                listed.Add((rank, new(ApplyCasing(name, order[rank], casing), value)));
            }
        }

        unlisted.AddRange(listed.OrderBy(static entry => entry.Rank).Select(static entry => entry.Header));
        return unlisted;
    }

    private static int IndexOf(IReadOnlyList<string> order, string name)
    {
        for (var i = 0; i < order.Count; i++)
        {
            if (string.Equals(order[i], name, StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }

        return -1;
    }

    private static string ApplyCasing(string name, string preferredSpelling, HeaderCasing casing) => casing switch
    {
        HeaderCasing.AsSpecified => preferredSpelling,
        HeaderCasing.LowerCase => name.ToLowerInvariant(),
        HeaderCasing.TitleCase => string.Join('-', name.Split('-').Select(static part =>
            part.Length == 0 ? part : char.ToUpperInvariant(part[0]) + part[1..].ToLower(CultureInfo.InvariantCulture))),
        _ => throw new ArgumentOutOfRangeException(nameof(casing), casing, null),
    };
}
