using Chameleon.Net.Profiles;
using Org.BouncyCastle.Tls;

namespace Chameleon.Net.Tls;

/// <summary>Serialises the handshake message BouncyCastle assembled, in profile order, with GREASE injected and padding sized last.
/// Needed because BouncyCastle's own writer emits empty-bodied extensions before non-empty ones regardless of dictionary order.</summary>
public interface IClientHelloEncoder
{
    ReadOnlyMemory<byte> Encode(ClientHello hello, TlsProfile profile);
}
