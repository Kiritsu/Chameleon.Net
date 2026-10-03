using System.Net;
using System.Net.Sockets;
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

        foreach (var profile in new[] { BuiltInProfiles.OkHttp4Android13, BuiltInProfiles.Chromium152Windows, BuiltInProfiles.Firefox156Windows })
        {
            var tls = profile.Tls.WithAlpn(["http/1.1"]);
            // One address for every connection: Google's and Cloudflare's DNS hand out different front ends, which don't share tickets.
            var transport = await PinnedTransport.ResolveAsync(host, cancellationToken);

            var first = await GetAsync(factory, transport, host, tls, cancellationToken);
            Assert.False(first.Resumed);

            // Even on one address, a load balancer can pick a node that can't decrypt the ticket: it then does a full handshake
            // and issues a new ticket, which the next attempt uses.
            var next = (Resumed: false, Response: "");
            for (var attempt = 0; attempt < 3 && !next.Resumed; attempt++)
            {
                next = await GetAsync(factory, transport, host, tls, cancellationToken);
            }

            Assert.True(next.Resumed, $"{host} ({transport.Address}) did not resume a {profile.Identity.Name} session in 3 attempts");
            Assert.StartsWith("HTTP/1.1 ", next.Response, StringComparison.Ordinal);
        }
    }

    [Fact(Explicit = true)]
    public async Task ResumedChromiumHandshakeShowsThePreSharedKeyInJa4()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var factory = new BouncyCastleTlsConnectionFactory();
        var tls = BuiltInProfiles.Chromium152Windows.Tls.WithAlpn(["http/1.1"]);

        await GetAsync(factory, new TcpTransport(), "tls.peet.ws", tls, cancellationToken, "/api/clean");
        var resumed = await GetAsync(factory, new TcpTransport(), "tls.peet.ws", tls, cancellationToken, "/api/clean");

        Assert.True(resumed.Resumed);
        // pre_shared_key added and, with http/1.1 alone, no ALPS: what Edge's resumed WebSocket connections show.
        Assert.Contains("t13d1516h1_8daaf6152771_3bf25d69fb96", resumed.Response, StringComparison.Ordinal);
    }

    private static async Task<(bool Resumed, string Response)> GetAsync(
        BouncyCastleTlsConnectionFactory factory, ITransport transport, string host, TlsProfile tls, CancellationToken cancellationToken, string path = "/")
    {
        var connection = await factory.ConnectAsync(transport, host, 443, tls, cancellationToken);
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

    /// <summary>Connects every time to the address the host resolved to first (IPv4 preferred), whatever the endpoint.</summary>
    private sealed class PinnedTransport(IPAddress address) : ITransport
    {
        public IPAddress Address => address;

        public static async Task<PinnedTransport> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
            return new PinnedTransport(addresses.FirstOrDefault(static a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses[0]);
        }

        public async Task<Stream> ConnectAsync(DnsEndPoint endpoint, CancellationToken cancellationToken = default)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(address, endpoint.Port, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }
    }
}
