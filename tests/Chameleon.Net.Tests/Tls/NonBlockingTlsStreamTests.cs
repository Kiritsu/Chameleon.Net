using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Org.BouncyCastle.Security;

namespace Chameleon.Net.Tests.Tls;

/// <summary>TLS on BouncyCastle's non-blocking mode, against a local TLS server (the OS stack, through SslStream).</summary>
public sealed class NonBlockingTlsStreamTests
{
    private const int IdleConnections = 200;

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    [Fact]
    public async Task PendingReadDoesNotBlockWrites()
    {
        using var certificate = TestCertificates.SelfSigned();
        await using var server = new EchoServer(certificate);
        await using var stream = await ConnectAsync(server.Port);

        var pendingRead = stream.ReadAsync(new byte[16], CancellationToken).AsTask();
        await Task.Delay(100, CancellationToken);
        Assert.False(pendingRead.IsCompleted);

        await stream.WriteAsync("ping"u8.ToArray(), CancellationToken).AsTask().WaitAsync(TimeSpan.FromSeconds(5), CancellationToken);

        Assert.True(await pendingRead.WaitAsync(TimeSpan.FromSeconds(5), CancellationToken) > 0);
    }

    /// <summary>The point of non-blocking mode: an idle connection waiting for data holds no thread. With BouncyCastle's blocking stream each
    /// pending read held a pool thread, so 200 idle connections (WebSockets, HTTP/2 connections) starved everything else queued on the pool.</summary>
    [Fact]
    public async Task IdleConnectionsDoNotHoldThreadPoolThreads()
    {
        using var certificate = TestCertificates.SelfSigned();
        await using var server = new EchoServer(certificate);
        var streams = new List<Stream>();
        try
        {
            for (var i = 0; i < IdleConnections; i++)
            {
                streams.Add(await ConnectAsync(server.Port));
            }

            var pendingReads = streams.Select(stream => stream.ReadAsync(new byte[16], CancellationToken).AsTask()).ToList();
            await Task.Delay(1000, CancellationToken);

            Assert.All(pendingReads, static read => Assert.False(read.IsCompleted));
            // Blocking reads each occupy a pool thread or sit queued for one; async socket reads are neither. Margin for other tests' work.
            Assert.InRange(ThreadPool.PendingWorkItemCount, 0, 50);

            // Every connection still works: one echo each.
            foreach (var stream in streams)
            {
                await stream.WriteAsync("x"u8.ToArray(), CancellationToken);
            }

            await Task.WhenAll(pendingReads).WaitAsync(TimeSpan.FromSeconds(30), CancellationToken);
        }
        finally
        {
            foreach (var stream in streams)
            {
                await stream.DisposeAsync();
            }
        }
    }

    private static async Task<Stream> ConnectAsync(int port)
    {
        var factory = new BouncyCastleTlsConnectionFactory(
            new ProfileTlsClientFactory(), new ClientHelloEncoder(new SecureRandom()), new TrustAnyCertificate(), new SecureRandom());
        var connection = await factory.ConnectAsync(new TcpTransport(), "127.0.0.1", port, BuiltInProfiles.OkHttp4Android13.Tls, CancellationToken);
        return connection.Stream;
    }

    /// <summary>Echoes whatever each client sends, fully async on the server side too.</summary>
    private sealed class EchoServer : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly X509Certificate2 _certificate;
        private readonly Task _accepting;

        public EchoServer(X509Certificate2 certificate)
        {
            _certificate = certificate;
            _listener.Start();
            _accepting = AcceptAsync();
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            await _accepting.ConfigureAwait(false);
        }

        private async Task AcceptAsync()
        {
            while (true)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync();
                }
                catch (Exception exception) when (exception is SocketException or ObjectDisposedException)
                {
                    return;
                }

                _ = EchoAsync(client);
            }
        }

        private async Task EchoAsync(TcpClient client)
        {
            using var _ = client;
            try
            {
                await using var ssl = new SslStream(client.GetStream());
                await ssl.AuthenticateAsServerAsync(_certificate);
                var buffer = new byte[4096];
                int read;
                while ((read = await ssl.ReadAsync(buffer)) > 0)
                {
                    await ssl.WriteAsync(buffer.AsMemory(0, read));
                }
            }
            catch (Exception exception) when (exception is IOException or ObjectDisposedException or System.Security.Authentication.AuthenticationException)
            {
                // Client went away.
            }
        }
    }
}
