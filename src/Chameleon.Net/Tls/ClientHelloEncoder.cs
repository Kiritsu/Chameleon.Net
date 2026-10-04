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

    /// <summary>Each call draws fresh GREASE values and, for Chrome-shuffled profiles, a fresh extension order: one call per connection.
    /// A connection that may send a second ClientHello (after a HelloRetryRequest) must use <see cref="ForConnection"/> instead.</summary>
    public ReadOnlyMemory<byte> Encode(ClientHello hello, TlsProfile profile)
    {
        ArgumentNullException.ThrowIfNull(hello);
        ArgumentNullException.ThrowIfNull(profile);
        return EncodeWith(hello, profile, Draw(profile), retry: false);
    }

    /// <summary>An encoder for one connection: every ClientHello it writes reuses the same GREASE values and extension order. RFC 8446
    /// wants the ClientHello after a HelloRetryRequest unchanged apart from key_share, cookie and pre_shared_key; BoringSSL keeps its
    /// GREASE seed and permutation per connection, and Go's server rejects a changed cipher suite list.</summary>
    public IClientHelloEncoder ForConnection() => new ConnectionEncoder(this);

    private static ReadOnlyMemory<byte> EncodeWith(ClientHello hello, TlsProfile profile, Choices choices, bool retry)
    {
        var extensions = choices.Layout;
        var greaseValues = choices.ExtensionGrease;

        using var body = new MemoryStream();
        TlsUtilities.WriteVersion(hello.Version, body);
        body.Write(hello.Random);
        TlsUtilities.WriteOpaque8(hello.SessionID, body);
        // BouncyCastle appends TLS_EMPTY_RENEGOTIATION_INFO_SCSV when the hello has no renegotiation_info; only the profile adds suites.
        int[] cipherSuites = profile.CipherSuites.Contains((ushort)CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
            ? hello.CipherSuites
            : [.. hello.CipherSuites.Where(static suite => suite != CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)];
        TlsUtilities.WriteUint16ArrayWithUint16Length(
            profile.Grease.HasFlag(GreasePlacement.CipherSuites) ? [choices.CipherSuite, .. cipherSuites] : cipherSuites, body);
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
                case ServerNameExtension when !hello.Extensions.ContainsKey(extension.Type):
                    // No SNI for IP-literal hosts.
                    break;
                default:
                    encoded.Add((extension.Type, ExtensionBody(hello, profile, extension, choices, retry)));
                    break;
            }
        }

        var unexpected = hello.Extensions.Keys
            .Where(type => type != ExtensionType.pre_shared_key && !profile.Extensions.Any(extension => extension.Type == type))
            .ToList();
        if (unexpected.Count > 0)
        {
            throw new InvalidOperationException(
                $"BouncyCastle produced extensions absent from the profile: {string.Join(", ", unexpected)}. The handshake state would not match the wire.");
        }

        // A resumption offer: RFC 8446 requires pre_shared_key last, and BoringSSL counts it when sizing the padding.
        hello.Extensions.TryGetValue(ExtensionType.pre_shared_key, out var preSharedKey);
        var preSharedKeyLength = preSharedKey is null ? 0 : 4 + preSharedKey.Length;

        if (padding is not null)
        {
            var lengthWithoutPadding = 4 + (int)body.Length + 2 + encoded.Sum(static entry => 4 + entry.Body.Length) + preSharedKeyLength;
            var paddingLength = PaddingLength(lengthWithoutPadding, padding.TargetClientHelloLength);
            if (paddingLength >= 0)
            {
                encoded.Insert(paddingPosition, (ExtensionType.padding, new byte[paddingLength]));
            }
        }

        if (preSharedKey is not null)
        {
            encoded.Add((ExtensionType.pre_shared_key, preSharedKey));
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

    private Choices Draw(TlsProfile profile)
    {
        var layout = Layout(profile);
        return new Choices(
            layout,
            DrawGreaseValues(layout.Count(static extension => extension is GreaseExtension)),
            Grease(_random.Next(GreaseCount)),
            Grease(_random.Next(GreaseCount)),
            Grease(_random.Next(GreaseCount)),
            Grease(_random.Next(GreaseCount)));
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

    private static byte[] ExtensionBody(ClientHello hello, TlsProfile profile, TlsExtension extension, Choices choices, bool retry)
    {
        if (!hello.Extensions.TryGetValue(extension.Type, out var produced))
        {
            throw new InvalidOperationException($"Profile lists extension {extension.Type} but BouncyCastle produced no body for it.");
        }

        return extension switch
        {
            SupportedGroupsExtension when profile.Grease.HasFlag(GreasePlacement.SupportedGroups) => PrependUint16(produced, 2, choices.Group),
            SupportedVersionsExtension when profile.Grease.HasFlag(GreasePlacement.SupportedVersions) => PrependUint16(produced, 1, choices.Version),
            SignatureAlgorithmsExtension when profile.Grease.HasFlag(GreasePlacement.SignatureAlgorithms) => PrependUint16(produced, 2, choices.SignatureAlgorithm),
            // BoringSSL uses one GREASE group for both supported_groups and key_share (seen in every Chromium capture). After a
            // HelloRetryRequest key_share must hold only the group the server asked for, and BoringSSL leaves GREASE out.
            KeyShareExtension when profile.Grease.HasFlag(GreasePlacement.KeyShare) && !retry => PrependGreaseKeyShare(produced, choices.Group),
            _ => produced,
        };
    }

    // Body is a length-prefixed uint16 list; insert a GREASE value at the front and fix the prefix.
    private static byte[] PrependUint16(byte[] body, int prefixLength, int grease)
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

        TlsUtilities.WriteUint16(grease, result, prefixLength);
        Buffer.BlockCopy(body, prefixLength, result, prefixLength + 2, body.Length - prefixLength);
        return result;
    }

    // Chrome's GREASE key_share entry: GREASE group with a single zero byte of key material.
    private static byte[] PrependGreaseKeyShare(byte[] body, int grease)
    {
        const int entryLength = 2 + 2 + 1;
        var result = new byte[body.Length + entryLength];
        TlsUtilities.WriteUint16(TlsUtilities.ReadUint16(body, 0) + entryLength, result, 0);
        TlsUtilities.WriteUint16(grease, result, 2);
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

    /// <summary>Everything random about one connection's ClientHello.</summary>
    private sealed record Choices(List<TlsExtension> Layout, int[] ExtensionGrease, int CipherSuite, int Group, int Version, int SignatureAlgorithm);

    private sealed class ConnectionEncoder(ClientHelloEncoder owner) : IClientHelloEncoder
    {
        private TlsProfile? _profile;
        private Choices? _choices;

        public ReadOnlyMemory<byte> Encode(ClientHello hello, TlsProfile profile)
        {
            ArgumentNullException.ThrowIfNull(hello);
            ArgumentNullException.ThrowIfNull(profile);
            // A second ClientHello on the same connection answers a HelloRetryRequest.
            var retry = _choices is not null && ReferenceEquals(_profile, profile);
            if (!retry)
            {
                _profile = profile;
                _choices = owner.Draw(profile);
            }

            return EncodeWith(hello, profile, _choices!, retry);
        }
    }
}
