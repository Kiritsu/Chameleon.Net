using System.Text;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Org.BouncyCastle.Security;

namespace Chameleon.Net.Tests.Tls;

/// <summary>Real network. Explicit: run with <c>dotnet test --solution Chameleon.Net.slnx -- --explicit only</c>.</summary>
public sealed class LiveHandshakeTests
{
    private readonly BouncyCastleTlsConnectionFactory _factory = new(
        new ProfileTlsClientFactory(), new ClientHelloEncoder(new SecureRandom()), new SystemCertificateValidator(), new SecureRandom());

    [Theory(Explicit = true)]
    [InlineData("www.cloudflare.com")]
    [InlineData("example.com")]
    public async Task OkHttpProfileNegotiatesH2(string host)
    {
        var connection = await _factory.ConnectAsync(
            new TcpTransport(), host, 443, BuiltInProfiles.OkHttp4Android13.Tls, TestContext.Current.CancellationToken);
        await using var stream = connection.Stream;

        Assert.Equal("h2", connection.NegotiatedProtocol);
    }

    [Theory(Explicit = true)]
    [InlineData("www.cloudflare.com")]
    [InlineData("example.com")]
    public async Task OkHttpWebSocketAlpnServesHttp11(string host)
    {
        var profile = BuiltInProfiles.OkHttp4Android13;
        var tls = profile.Tls with
        {
            Extensions = [.. profile.Tls.Extensions.Select(e => e is AlpnExtension ? new AlpnExtension(profile.WebSocket.Alpn!) : e)],
        };
        var cancellationToken = TestContext.Current.CancellationToken;
        var connection = await _factory.ConnectAsync(new TcpTransport(), host, 443, tls, cancellationToken);
        await using var stream = connection.Stream;

        Assert.Equal("http/1.1", connection.NegotiatedProtocol);

        await stream.WriteAsync(Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"), cancellationToken);
        var buffer = new byte[64];
        var read = await stream.ReadAsync(buffer, cancellationToken);

        Assert.StartsWith("HTTP/1.1 ", Encoding.ASCII.GetString(buffer, 0, read), StringComparison.Ordinal);
    }

    [Theory(Explicit = true)]
    [InlineData("wrong.host.badssl.com")]
    [InlineData("expired.badssl.com")]
    [InlineData("self-signed.badssl.com")]
    [InlineData("untrusted-root.badssl.com")]
    public async Task RejectsInvalidCertificates(string host)
    {
        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await _factory.ConnectAsync(new TcpTransport(), host, 443, BuiltInProfiles.OkHttp4Android13.Tls, TestContext.Current.CancellationToken));
    }
}
