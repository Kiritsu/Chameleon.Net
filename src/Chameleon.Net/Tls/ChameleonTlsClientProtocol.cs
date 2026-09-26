using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Chameleon.Net.Profiles;
using Org.BouncyCastle.Tls;

namespace Chameleon.Net.Tls;

/// <summary>Lets BouncyCastle assemble the ClientHello and own the handshake state, but writes the message bytes itself so extension order survives.</summary>
internal sealed class ChameleonTlsClientProtocol : TlsClientProtocol
{
    private readonly TlsProfile _profile;
    private readonly IClientHelloEncoder _encoder;

    public ChameleonTlsClientProtocol(Stream stream, TlsProfile profile, IClientHelloEncoder encoder)
        : base(stream)
    {
        _profile = profile;
        _encoder = encoder;
    }

    public string? NegotiatedApplicationProtocol => Context.SecurityParameters.ApplicationProtocol?.GetUtf8Decoding();

    protected override void SendClientHelloMessage()
    {
        var encoded = _encoder.Encode(m_clientHello, _profile);
        var message = MemoryMarshal.TryGetArray(encoded, out var segment) && segment.Offset == 0 && segment.Count == segment.Array!.Length
            ? segment.Array
            : encoded.ToArray();

        HandshakeHash(this).Update(message, 0, message.Length);
        SafeWriteRecord(ContentType.handshake, message, 0, message.Length);
    }

    // BouncyCastle's writer reorders extensions (empty bodies first) and the transcript hash is internal; this is the one seam it does not expose.
    // Pinned by BouncyCastleInternalsTests: a BouncyCastle upgrade that renames it fails there, not at handshake time.
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "m_handshakeHash")]
    private static extern ref TlsHandshakeHash HandshakeHash(TlsProtocol protocol);
}
