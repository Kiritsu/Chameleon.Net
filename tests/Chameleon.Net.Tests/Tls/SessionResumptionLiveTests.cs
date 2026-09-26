using System.Text;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;

namespace Chameleon.Net.Tests.Tls;

/// <summary>Real network. Explicit: run with <c>dotnet test --solution Chameleon.Net.slnx -- --explicit only</c>.</summary>
public sealed class SessionResumptionLiveTests
{
    [Theory(Explicit = true)]
    [InlineData("www.cloudflare.com")]
    [InlineData("www.google.com")]
    [InlineData("tls.peet.ws")]
    public async Task SecondConnectionResumesWithTheTicketFromTheFirst(string host)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var factory = new BouncyCastleTlsConnectionFactory();

        foreach (var profile in new[] { BuiltInProfiles.OkHttp4Android13.Tls, BuiltInProfiles.Chromium152Windows.Tls, BuiltInProfiles.Firefox156Windows.Tls })
        {
            var tls = profile.WithAlpn(["http/1.1"]);

            var first = await GetAsync(factory, host, tls, cancellationToken);
            var second = await GetAsync(factory, host, tls, cancellationToken);

            Assert.False(first.Resumed);
            Assert.True(second.Resumed, $"{host} did not resume");
            Assert.StartsWith("HTTP/1.1 ", second.Response, StringComparison.Ordinal);
        }
    }

    [Fact(Explicit = true)]
    public async Task ResumedChromiumHandshakeShowsThePreSharedKeyInJa4()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var factory = new BouncyCastleTlsConnectionFactory();
        var tls = BuiltInProfiles.Chromium152Windows.Tls.WithAlpn(["http/1.1"]);

        await GetAsync(factory, "tls.peet.ws", tls, cancellationToken, "/api/clean");
        var resumed = await GetAsync(factory, "tls.peet.ws", tls, cancellationToken, "/api/clean");

        Assert.True(resumed.Resumed);
        // 17 extensions now (pre_shared_key added); the sorted-extension hash changes accordingly.
        Assert.Contains("t13d1517h1_", resumed.Response, StringComparison.Ordinal);
    }

    private static async Task<(bool Resumed, string Response)> GetAsync(
        BouncyCastleTlsConnectionFactory factory, string host, TlsProfile tls, CancellationToken cancellationToken, string path = "/")
    {
        var connection = await factory.ConnectAsync(new TcpTransport(), host, 443, tls, cancellationToken);
        await using var stream = connection.Stream;

        await stream.WriteAsync(Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"), cancellationToken);
        // Read to the end: servers send their tickets after the handshake, and they are only seen by reading.
        using var response = new MemoryStream();
        try
        {
            await stream.CopyToAsync(response, cancellationToken);
        }
        catch (Org.BouncyCastle.Tls.TlsNoCloseNotifyException)
        {
            // Google hangs up without close_notify.
        }

        return (connection.SessionResumed, Encoding.ASCII.GetString(response.ToArray()));
    }
}
