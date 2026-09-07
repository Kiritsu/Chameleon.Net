using Chameleon.Net.Profiles;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace Chameleon.Net.Tls;

/// <summary>Turns a <see cref="TlsProfile"/> into the exact ClientHello BouncyCastle will send, with GREASE resolved and key shares generated in profile order.</summary>
public interface IClientHelloBuilder
{
    ClientHelloPlan Build(TlsProfile profile, string serverName, TlsCrypto crypto, SecureRandom random);
}

/// <summary>What the overridden TlsClientProtocol.SendClientHello needs to populate before calling SendClientHelloMessage.</summary>
public sealed record ClientHelloPlan(
    ClientHello Hello,
    IDictionary<int, byte[]> Extensions,
    IDictionary<int, TlsAgreement> Agreements);
