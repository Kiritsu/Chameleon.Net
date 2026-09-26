using System.Collections.Frozen;

namespace Chameleon.Net.Fingerprints;

/// <summary>The 16 reserved code points from RFC 8701, reused verbatim across cipher suites, extensions, named groups, versions and signature schemes.</summary>
internal static class GreaseValues
{
    private static readonly FrozenSet<ushort> Values = FrozenSet.Create<ushort>(
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA);

    public static bool Contains(ushort value) => Values.Contains(value);
}
