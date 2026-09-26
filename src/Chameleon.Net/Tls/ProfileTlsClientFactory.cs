using Chameleon.Net.Profiles;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace Chameleon.Net.Tls;

public sealed class ProfileTlsClientFactory : ITlsClientFactory
{
    public TlsClient Create(TlsProfile profile, string serverName, TlsCrypto crypto, IServerCertificateValidator certificateValidator) =>
        new ProfileTlsClient(crypto, profile, serverName, certificateValidator);
}
