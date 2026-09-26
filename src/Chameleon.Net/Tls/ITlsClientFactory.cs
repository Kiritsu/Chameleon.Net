using Chameleon.Net.Profiles;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace Chameleon.Net.Tls;

/// <summary>Produces the BouncyCastle TlsClient whose hooks (cipher suites, groups, key-share groups, versions, extensions) supply the ClientHello <em>content</em> for a profile.
/// BouncyCastle keeps ownership of key agreement state; wire shape is <see cref="IClientHelloEncoder"/>'s job.</summary>
public interface ITlsClientFactory
{
    TlsClient Create(TlsProfile profile, string serverName, TlsCrypto crypto, IServerCertificateValidator certificateValidator);
}
