using System.Buffers.Binary;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;

namespace Chameleon.Net.Tests.Tls;

public sealed class PostQuantumKeyShareTests
{
    [Fact]
    public async Task HybridShareIsSentInProfileOrderAfterGrease()
    {
        var profile = PostQuantumLiveTests.WithKeyShares(BuiltInProfiles.OkHttp4Android13, groups: [0x11EC, 29, 23, 24], keyShares: [0x11EC, 29]).Tls
            with { Grease = GreasePlacement.KeyShare };

        var record = await ClientHelloCapture.CaptureAsync(profile, "example.com");
        var entries = KeyShareEntries(record);

        Assert.Equal(3, entries.Count);
        Assert.Equal(0x0A0A, entries[0].Group & 0x0F0F);
        Assert.Equal(1, entries[0].Length);
        Assert.Equal((0x11EC, 1184 + 32), (entries[1].Group, entries[1].Length));
        Assert.Equal((29, 32), (entries[2].Group, entries[2].Length));
    }

    [Fact]
    public async Task ProfilesWithoutHybridGroupsAreUnchanged()
    {
        var entries = KeyShareEntries(await ClientHelloCapture.CaptureAsync(BuiltInProfiles.OkHttp4Android13.Tls, "example.com"));

        Assert.Equal([(29, 32)], entries.Select(static e => (e.Group, e.Length)));
    }

    private static List<(int Group, int Length)> KeyShareEntries(byte[] record)
    {
        var body = record.AsSpan(5 + 4);
        var offset = 2 + 32;
        offset += 1 + body[offset];
        offset += 2 + BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 1 + body[offset];
        var extensions = body.Slice(offset + 2, BinaryPrimitives.ReadUInt16BigEndian(body[offset..]));

        while (BinaryPrimitives.ReadUInt16BigEndian(extensions) != 51)
        {
            extensions = extensions[(4 + BinaryPrimitives.ReadUInt16BigEndian(extensions[2..]))..];
        }

        var shares = extensions.Slice(6, BinaryPrimitives.ReadUInt16BigEndian(extensions[4..]));
        var result = new List<(int, int)>();
        while (!shares.IsEmpty)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(shares[2..]);
            result.Add((BinaryPrimitives.ReadUInt16BigEndian(shares), length));
            shares = shares[(4 + length)..];
        }

        return result;
    }
}
