using Chameleon.Net.Profiles;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;

namespace Chameleon.Net.Tls;

public sealed class ClientHelloEncoder : IClientHelloEncoder
{
    private const int GreaseCount = 16;
    private const int MaxHandshakeMessageSize = 16384;

    private readonly SecureRandom _random;

    public ClientHelloEncoder(SecureRandom random)
    {
        ArgumentNullException.ThrowIfNull(random);
        _random = random;
    }

    public ReadOnlyMemory<byte> Encode(ClientHello hello, TlsProfile profile)
    {
        ArgumentNullException.ThrowIfNull(hello);
        ArgumentNullException.ThrowIfNull(profile);

        var extensions = Layout(profile);
        var greaseValues = DrawGreaseValues(extensions.Count(static extension => extension is GreaseExtension));

        using var body = new MemoryStream();
        TlsUtilities.WriteVersion(hello.Version, body);
        body.Write(hello.Random);
        TlsUtilities.WriteOpaque8(hello.SessionID, body);
        TlsUtilities.WriteUint16ArrayWithUint16Length(CipherSuites(hello, profile), body);
        TlsUtilities.WriteOpaque8([0], body);

        var encoded = new List<(int Type, byte[] Body)>(extensions.Count);
        var greaseIndex = 0;
        PaddingExtension? padding = null;
        var paddingPosition = -1;

        foreach (var extension in extensions)
        {
            switch (extension)
            {
                case PaddingExtension request:
                    padding = request;
                    paddingPosition = encoded.Count;
                    break;
                case GreaseExtension grease:
                    encoded.Add((greaseValues[greaseIndex++], grease.Body.ToArray()));
                    break;
                default:
                    encoded.Add((extension.Type, ExtensionBody(hello, profile, extension)));
                    break;
            }
        }

        var unexpected = hello.Extensions.Keys.Where(type => !profile.Extensions.Any(extension => extension.Type == type)).ToList();
        if (unexpected.Count > 0)
        {
            throw new InvalidOperationException(
                $"BouncyCastle produced extensions absent from the profile: {string.Join(", ", unexpected)}. The handshake state would not match the wire.");
        }

        if (padding is not null)
        {
            var lengthWithoutPadding = 4 + (int)body.Length + 2 + encoded.Sum(static entry => 4 + entry.Body.Length);
            var paddingLength = PaddingLength(lengthWithoutPadding, padding.TargetClientHelloLength);
            if (paddingLength >= 0)
            {
                encoded.Insert(paddingPosition, (ExtensionType.padding, new byte[paddingLength]));
            }
        }

        using var extensionBytes = new MemoryStream();
        foreach (var (type, extensionBody) in encoded)
        {
            TlsUtilities.WriteUint16(type, extensionBytes);
            TlsUtilities.WriteOpaque16(extensionBody, extensionBytes);
        }

        TlsUtilities.WriteOpaque16(extensionBytes.ToArray(), body);

        var handshake = new byte[4 + body.Length];
        handshake[0] = (byte)HandshakeType.client_hello;
        TlsUtilities.WriteUint24((int)body.Length, handshake, 1);
        body.Position = 0;
        body.ReadExactly(handshake.AsSpan(4));

        if (handshake.Length > MaxHandshakeMessageSize)
        {
            throw new InvalidOperationException("ClientHello exceeds a single TLS record.");
        }

        return handshake;
    }

    private List<TlsExtension> Layout(TlsProfile profile)
    {
        var extensions = profile.Extensions.ToList();
        if (profile.Shuffle != ExtensionShufflePolicy.Chrome)
        {
            return extensions;
        }

        var first = 0;
        while (first < extensions.Count && extensions[first] is GreaseExtension)
        {
            first++;
        }

        var last = extensions.Count;
        while (last > first && extensions[last - 1] is GreaseExtension or PaddingExtension)
        {
            last--;
        }

        for (var i = last - 1; i > first; i--)
        {
            var j = first + _random.Next(i - first + 1);
            (extensions[i], extensions[j]) = (extensions[j], extensions[i]);
        }

        return extensions;
    }

    private int[] DrawGreaseValues(int count)
    {
        var values = new int[count];
        for (var i = 0; i < count; i++)
        {
            do
            {
                values[i] = Grease(_random.Next(GreaseCount));
            }
            while (i > 0 && values[i] == values[i - 1]);
        }

        return values;
    }

    private int[] CipherSuites(ClientHello hello, TlsProfile profile)
    {
        var suites = hello.CipherSuites;
        return profile.Grease.HasFlag(GreasePlacement.CipherSuites)
            ? [Grease(_random.Next(GreaseCount)), .. suites]
            : suites;
    }

    private byte[] ExtensionBody(ClientHello hello, TlsProfile profile, TlsExtension extension)
    {
        if (!hello.Extensions.TryGetValue(extension.Type, out var produced))
        {
            throw new InvalidOperationException($"Profile lists extension {extension.Type} but BouncyCastle produced no body for it.");
        }

        return extension switch
        {
            SupportedGroupsExtension when profile.Grease.HasFlag(GreasePlacement.SupportedGroups) => PrependUint16(produced, 2),
            SupportedVersionsExtension when profile.Grease.HasFlag(GreasePlacement.SupportedVersions) => PrependUint16(produced, 1),
            KeyShareExtension when profile.Grease.HasFlag(GreasePlacement.KeyShare) => PrependGreaseKeyShare(produced),
            _ => produced,
        };
    }

    // Body is a length-prefixed uint16 list; insert a GREASE value at the front and fix the prefix.
    private byte[] PrependUint16(byte[] body, int prefixLength)
    {
        var result = new byte[body.Length + 2];
        var listLength = prefixLength == 1 ? body[0] : TlsUtilities.ReadUint16(body, 0);
        if (prefixLength == 1)
        {
            result[0] = (byte)(listLength + 2);
        }
        else
        {
            TlsUtilities.WriteUint16(listLength + 2, result, 0);
        }

        TlsUtilities.WriteUint16(Grease(_random.Next(GreaseCount)), result, prefixLength);
        Buffer.BlockCopy(body, prefixLength, result, prefixLength + 2, body.Length - prefixLength);
        return result;
    }

    // Chrome's GREASE key_share entry: GREASE group with a single zero byte of key material.
    private byte[] PrependGreaseKeyShare(byte[] body)
    {
        const int entryLength = 2 + 2 + 1;
        var result = new byte[body.Length + entryLength];
        TlsUtilities.WriteUint16(TlsUtilities.ReadUint16(body, 0) + entryLength, result, 0);
        TlsUtilities.WriteUint16(Grease(_random.Next(GreaseCount)), result, 2);
        TlsUtilities.WriteUint16(1, result, 4);
        result[6] = 0;
        Buffer.BlockCopy(body, 2, result, 2 + entryLength, body.Length - 2);
        return result;
    }

    // BoringSSL rule (RFC 7685): pad only when the message would land in (0xFF, target); the extension itself costs 4 bytes.
    private static int PaddingLength(int lengthWithoutPadding, int target)
    {
        if (lengthWithoutPadding <= 0xFF || lengthWithoutPadding >= target)
        {
            return -1;
        }

        var paddingLength = target - lengthWithoutPadding;
        return paddingLength >= 4 + 1 ? paddingLength - 4 : 1;
    }

    private static int Grease(int index) => 0x0A0A + 0x1010 * index;
}
