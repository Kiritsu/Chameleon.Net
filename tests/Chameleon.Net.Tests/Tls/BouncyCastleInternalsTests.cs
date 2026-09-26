using System.Reflection;
using Org.BouncyCastle.Tls;

namespace Chameleon.Net.Tests.Tls;

/// <summary>Pins the BouncyCastle seams ChameleonTlsClientProtocol depends on. If one fails after a BouncyCastle upgrade, the ClientHello override needs revisiting before anything else.</summary>
public sealed class BouncyCastleInternalsTests
{
    private const BindingFlags Instance = BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public;

    [Fact]
    public void HandshakeHashFieldIsReachable()
    {
        var field = typeof(TlsProtocol).GetField("m_handshakeHash", Instance);

        Assert.NotNull(field);
        Assert.True(typeof(TlsHandshakeHash).IsAssignableFrom(field.FieldType));
    }

    [Fact]
    public void SendClientHelloMessageIsOverridable()
    {
        var method = typeof(TlsClientProtocol).GetMethod("SendClientHelloMessage", Instance, Type.EmptyTypes);

        Assert.NotNull(method);
        Assert.True(method.IsVirtual && method.IsFamily);
    }

    [Fact]
    public void ClientHelloStateIsProtected()
    {
        var field = typeof(TlsClientProtocol).GetField("m_clientHello", Instance);

        Assert.NotNull(field);
        Assert.True(field.IsFamily);
        Assert.Equal(typeof(ClientHello), field.FieldType);
    }

    /// <summary>Hybrid post-quantum shares are registered here so BouncyCastle finds them when the ServerHello arrives.</summary>
    [Fact]
    public void ClientAgreementsAreProtectedAndMutable()
    {
        var field = typeof(TlsClientProtocol).GetField("m_clientAgreements", Instance);

        Assert.NotNull(field);
        Assert.True(field.IsFamily);
        Assert.True(typeof(IDictionary<int, Org.BouncyCastle.Tls.Crypto.TlsAgreement>).IsAssignableFrom(field.FieldType));
    }

    /// <summary>CompressedCertificate support replays BouncyCastle's Certificate branch. It also relies on ProcessHandshakeQueue having
    /// hashed the message before dispatch (checked end to end by the explicit compressed-certificate live test).</summary>
    [Theory]
    [InlineData("Handle13HandshakeMessage")]
    [InlineData("Skip13CertificateRequest")]
    [InlineData("Receive13ServerCertificate")]
    public void CertificateHandlingSeamsAreOverridable(string name)
    {
        var method = typeof(TlsClientProtocol).GetMethod(name, Instance);

        Assert.NotNull(method);
        Assert.True(method.IsVirtual && method.IsFamily);
    }

    [Theory]
    [InlineData("CS_SERVER_ENCRYPTED_EXTENSIONS", 5)]
    [InlineData("CS_SERVER_CERTIFICATE", 7)]
    [InlineData("CS_SERVER_CERTIFICATE_REQUEST", 11)]
    public void ConnectionStatesKeepTheirValues(string name, short value)
    {
        var field = typeof(TlsProtocol).GetField(name, BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);

        Assert.NotNull(field);
        Assert.Equal(value, field.GetRawConstantValue());
    }
}
