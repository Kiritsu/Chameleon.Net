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
}
