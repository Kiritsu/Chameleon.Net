using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Chameleon.Net.Tests.Tls;

/// <summary>The resumption ClientHello, checked against an independent RFC 8446 key schedule built on .NET's HKDF. No network.</summary>
public sealed class SessionResumptionTests
{
    private static readonly byte[] Psk = [.. Enumerable.Range(1, 32).Select(static i => (byte)i)];
    private static readonly byte[] Identity = [.. Enumerable.Range(0, 120).Select(static i => (byte)(i * 7))];

    [Theory]
    [MemberData(nameof(Profiles))]
    public void PreSharedKeyIsLastWithTheTicketAgeAndAValidResumptionBinder(string name)
    {
        var profile = name == "okhttp" ? BuiltInProfiles.OkHttp4Android13.Tls : BuiltInProfiles.Chromium152Windows.Tls;
        const uint ageAdd = 0xFFFF_0000;
        var ticket = new SessionTicket(Identity, Psk, PrfAlgorithm.tls13_hkdf_sha256, CryptoHashAlgorithm.sha256, ageAdd,
            Stopwatch.GetTimestamp() - Stopwatch.Frequency * 5, TimeSpan.FromHours(1));

        var record = Capture(profile, ticket);
        var hello = record.AsSpan(5, BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(3))).ToArray();
        var extensions = Extensions(hello);

        Assert.Equal(41, extensions[^1].Type);
        Assert.Equal(extensions.Count, extensions.Select(static e => e.Type).Distinct().Count());
        var body = extensions[^1].Body;

        // identities: one entry, our identity, obfuscated age = age in ms + age_add (mod 2^32).
        Assert.Equal(2 + Identity.Length + 4, BinaryPrimitives.ReadUInt16BigEndian(body));
        Assert.Equal(Identity, body.AsSpan(4, Identity.Length).ToArray());
        var age = unchecked(BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(4 + Identity.Length)) - ageAdd);
        Assert.InRange(age, 5000u, 60_000u);

        // binders: one 32-byte binder over the ClientHello truncated before the binders list.
        var binders = body.AsSpan(2 + 2 + Identity.Length + 4);
        Assert.Equal(33, BinaryPrimitives.ReadUInt16BigEndian(binders));
        Assert.Equal(32, binders[2]);
        var truncated = hello.AsSpan(0, hello.Length - 35);
        Assert.Equal(ExpectedBinder(Psk, SHA256.HashData(truncated)), binders[3..].ToArray());
    }

    [Fact]
    public void TheResumptionHelloKeepsTheProfileFingerprintApartFromPreSharedKey()
    {
        var profile = BuiltInProfiles.Chromium152Windows.Tls;
        var ticket = new SessionTicket(Identity, Psk, PrfAlgorithm.tls13_hkdf_sha256, CryptoHashAlgorithm.sha256, 0, Stopwatch.GetTimestamp(), TimeSpan.FromHours(1));

        var fresh = TlsFingerprinter.Compute(ClientHelloParser.Parse(Capture(profile, ticket: null)));
        var resumed = TlsFingerprinter.Compute(ClientHelloParser.Parse(Capture(profile, ticket)));

        Assert.StartsWith("t13d1516h2_", fresh.Ja4, StringComparison.Ordinal);
        // Both seen from real browsers on tls.peet.ws: a fresh Chromium 152 connection, and a resumed Edge 153 one (same TLS stack).
        Assert.Equal("t13d1516h2_8daaf6152771_806a8c22fdea", fresh.Ja4);
        Assert.Equal("t13d1517h2_8daaf6152771_a87ad97598a9", resumed.Ja4);
    }

    [Fact]
    public void CacheHandsOutEachTicketOnceAndSkipsExpiredOnes()
    {
        var cache = new TlsSessionCache();
        var okhttp = BuiltInProfiles.OkHttp4Android13.Tls;
        var validator = new TrustAnyCertificate();
        var expired = new SessionTicket([1], Psk, 0, CryptoHashAlgorithm.sha256, 0, Stopwatch.GetTimestamp(), TimeSpan.Zero);
        var live = new SessionTicket([2], Psk, 0, CryptoHashAlgorithm.sha256, 0, Stopwatch.GetTimestamp(), TimeSpan.FromHours(1));

        cache.Add("example.com", 443, okhttp, validator, expired);
        cache.Add("example.com", 443, okhttp, validator, live);

        Assert.Same(live, cache.Take("example.com", 443, okhttp, validator));
        Assert.Null(cache.Take("example.com", 443, okhttp, validator));
    }

    [Fact]
    public void TicketsAreSharedAcrossAlpnVariantsButNotAcrossProfilesOrValidators()
    {
        var cache = new TlsSessionCache();
        var validator = new TrustAnyCertificate();
        void Add(TlsProfile profile) =>
            cache.Add("example.com", 443, profile, validator, new SessionTicket([1], Psk, 0, CryptoHashAlgorithm.sha256, 0, Stopwatch.GetTimestamp(), TimeSpan.FromHours(1)));

        var okhttp = BuiltInProfiles.OkHttp4Android13.Tls;
        Add(okhttp);
        Assert.Null(cache.Take("example.com", 443, BuiltInProfiles.Chromium152Windows.Tls, validator));
        Assert.Null(cache.Take("example.com", 8443, okhttp, validator));
        // A resumed session skips certificate validation: a stricter validator must not use a ticket the lax one obtained.
        Assert.Null(cache.Take("example.com", 443, okhttp, new SystemCertificateValidator()));
        // OkHttp's WebSocket connection (ALPN http/1.1 only) resumes the session of its REST calls: one Conscrypt cache per host.
        Assert.NotNull(cache.Take("example.com", 443, okhttp.WithAlpn(["http/1.1"]), validator));

        // Chromium and Edge send identical ClientHellos, but rotating between them must not let one resume the other's session.
        Add(BuiltInProfiles.Chromium152Windows.Tls);
        Assert.Null(cache.Take("example.com", 443, BuiltInProfiles.Edge153Windows.Tls, validator));
        Assert.NotNull(cache.Take("example.com", 443, BuiltInProfiles.Chromium152Windows.Tls.WithAlpn(["http/1.1"]), validator));
    }

    /// <summary>End to end against the OS TLS stack (SChannel on Windows) through Kestrel: tickets it issues are taken and accepted.</summary>
    [Fact]
    public async Task LocalTls13ServerAcceptsTheTicketOnTheNextConnection()
    {
        using var certificate = TestCertificates.SelfSigned();
        await using var server = await KestrelHttp2Server.StartAsync(static app => app.MapGet("/", static () => "ok"), certificate: certificate);
        var factory = new BouncyCastleTlsConnectionFactory(
            new ProfileTlsClientFactory(), new ClientHelloEncoder(new SecureRandom()), new TrustAnyCertificate(), new SecureRandom());
        var tls = BuiltInProfiles.OkHttp4Android13.Tls.WithAlpn(["http/1.1"]);
        var port = server.Url("/").Port;

        var first = await GetAsync(factory, port, tls);
        var second = await GetAsync(factory, port, tls);

        Assert.False(first.Resumed);
        Assert.Contains("\r\nok\r\n", first.Response, StringComparison.Ordinal);
        Assert.True(second.Resumed);
        Assert.Contains("\r\nok\r\n", second.Response, StringComparison.Ordinal);
    }

    /// <summary>One OkHttpClient serves REST and WebSockets from one session cache; a shared <see cref="TlsSessionCache"/> does the same.</summary>
    [Fact]
    public async Task WebSocketResumesTheSessionOfAnEarlierHttpRequest()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var certificate = TestCertificates.SelfSigned();
        await using var server = await KestrelHttp2Server.StartAsync(static app =>
        {
            app.UseWebSockets();
            app.MapGet("/", static () => "ok");
            app.Map("/ws", static async context =>
            {
                using var socket = await context.WebSockets.AcceptWebSocketAsync();
                await socket.CloseAsync(System.Net.WebSockets.WebSocketCloseStatus.NormalClosure, null, context.RequestAborted);
            });
        }, certificate: certificate);
        var logs = new CapturingLoggerProvider();
        using var loggerFactory = LoggerFactory.Create(builder =>
            builder.AddProvider(logs).SetMinimumLevel(LogLevel.Debug));
        var options = new ChameleonOptions
        {
            CertificateValidator = new TrustAnyCertificate(),
            TlsSessionCache = new TlsSessionCache(),
            LoggerFactory = loggerFactory,
        };
        var profile = BuiltInProfiles.OkHttp4Android13;
        var port = server.Url("/").Port;

        using (var client = new HttpClient(new Chameleon.Net.Http.ChameleonHttpMessageHandler(profile, options)))
        {
            Assert.Equal("ok", await client.GetStringAsync(new Uri($"https://127.0.0.1:{port}/"), cancellationToken));
        }

        using var webSocket = await new Chameleon.Net.WebSockets.ChameleonWebSocketConnector(options)
            .ConnectAsync(new Uri($"wss://127.0.0.1:{port}/ws"), profile, cancellationToken: cancellationToken);

        Assert.Contains(logs.Messages, static m => m.StartsWith("Connected to 127.0.0.1:", StringComparison.Ordinal) && m.EndsWith("protocol h2, TLS session resumed: False", StringComparison.Ordinal));
        Assert.Contains(logs.Messages, static m => m.StartsWith("WebSocket to wss://127.0.0.1:", StringComparison.Ordinal) && m.EndsWith("TLS session resumed: True", StringComparison.Ordinal));
    }

    /// <summary>Only a failure before the ServerHello may be the ticket's fault and earns a retry without it.</summary>
    [Fact]
    public async Task TicketlessRetryOnlyFollowsFailuresBeforeTheServerHello()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var tls = BuiltInProfiles.OkHttp4Android13.Tls;
        var bogus = new SessionTicket([7, 7, 7], Psk, PrfAlgorithm.tls13_hkdf_sha256, CryptoHashAlgorithm.sha256, 0, Stopwatch.GetTimestamp(), TimeSpan.FromHours(1));

        // Before the ServerHello (SChannel does this for a ticket it can't use): maybe the ticket's fault, so one retry without it.
        Assert.Equal(2, await ConnectionsUntilFailure(serverHello: null));

        // After the ServerHello (here a malformed one): not the ticket's doing, so no second connection.
        Assert.Equal(1, await ConnectionsUntilFailure(serverHello: [0x16, 0x03, 0x03, 0x00, 0x08, 0x02, 0x00, 0x00, 0x04, 0x03, 0x03, 0x00, 0x00]));

        async Task<int> ConnectionsUntilFailure(byte[]? serverHello)
        {
            using var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            listener.Start();
            var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
            var serving = Task.Run(async () =>
            {
                while (true)
                {
                    using var client = await listener.AcceptTcpClientAsync(cancellationToken);
                    var stream = client.GetStream();
                    await stream.ReadAtLeastAsync(new byte[16384], 1, throwOnEndOfStream: false, cancellationToken);
                    if (serverHello is not null)
                    {
                        await stream.WriteAsync(serverHello, cancellationToken);
                        await stream.ReadAtLeastAsync(new byte[16384], 1, throwOnEndOfStream: false, cancellationToken);
                    }
                }
            }, cancellationToken);

            var validator = new TrustAnyCertificate();
            var (factory, transport) = FactoryWithTicket(validator, "127.0.0.1", port, tls, bogus);
            await Assert.ThrowsAnyAsync<IOException>(() => factory.ConnectAsync(transport, "127.0.0.1", port, tls, cancellationToken));
            listener.Stop();
            await Assert.ThrowsAnyAsync<Exception>(() => serving.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken));
            return transport.Connections;
        }
    }

    private static (BouncyCastleTlsConnectionFactory Factory, CountingTransport Transport) FactoryWithTicket(
        IServerCertificateValidator validator, string host, int port, TlsProfile tls, SessionTicket ticket)
    {
        var factory = new BouncyCastleTlsConnectionFactory(new ProfileTlsClientFactory(), new ClientHelloEncoder(new SecureRandom()), validator, new SecureRandom());
        factory.SessionCache.Add(host, port, tls, validator, ticket);
        return (factory, new CountingTransport());
    }

    private sealed class CountingTransport : ITransport
    {
        private int _connections;

        public int Connections => Volatile.Read(ref _connections);

        public Task<Stream> ConnectAsync(System.Net.DnsEndPoint endpoint, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _connections);
            return new TcpTransport().ConnectAsync(endpoint, cancellationToken);
        }
    }

    private static async Task<(bool Resumed, string Response)> GetAsync(BouncyCastleTlsConnectionFactory factory, int port, TlsProfile tls)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var connection = await factory.ConnectAsync(new TcpTransport(), "127.0.0.1", port, tls, cancellationToken);
        await using var stream = connection.Stream;
        await stream.WriteAsync(Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"), cancellationToken);

        using var response = new MemoryStream();
        try
        {
            await stream.CopyToAsync(response, cancellationToken);
        }
        catch (TlsNoCloseNotifyException)
        {
        }

        return (connection.SessionResumed, Encoding.ASCII.GetString(response.ToArray()));
    }

    public static TheoryData<string> Profiles => ["okhttp", "chromium"];

    private static byte[] Capture(TlsProfile profile, SessionTicket? ticket)
    {
        var random = new SecureRandom();
        using var stream = new CapturingStream();
        var protocol = new ChameleonTlsClientProtocol(stream, profile, new ClientHelloEncoder(random), ticket, onTicket: null);
        var client = new ProfileTlsClient(new BcTlsCrypto(random), profile, "example.com", new SystemCertificateValidator()) { Resumption = ticket };

        Assert.ThrowsAny<Exception>(() => protocol.Connect(client));
        return stream.Written;
    }

    // RFC 8446 §4.2.11.2 and §7.1, from .NET's HKDF rather than BouncyCastle's.
    private static byte[] ExpectedBinder(byte[] psk, byte[] truncatedHash)
    {
        var early = HKDF.Extract(HashAlgorithmName.SHA256, psk, new byte[32]);
        var binderKey = ExpandLabel(early, "res binder", SHA256.HashData([]));
        var finishedKey = ExpandLabel(binderKey, "finished", []);
        return HMACSHA256.HashData(finishedKey, truncatedHash);
    }

    private static byte[] ExpandLabel(byte[] secret, string label, byte[] context)
    {
        var fullLabel = Encoding.ASCII.GetBytes("tls13 " + label);
        byte[] info = [0, 32, (byte)fullLabel.Length, .. fullLabel, (byte)context.Length, .. context];
        return HKDF.Expand(HashAlgorithmName.SHA256, secret, 32, info);
    }

    private static List<(int Type, byte[] Body)> Extensions(byte[] hello)
    {
        var body = hello.AsSpan(4);
        var offset = 2 + 32;
        offset += 1 + body[offset];
        offset += 2 + BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 1 + body[offset];

        var extensions = body.Slice(offset + 2, BinaryPrimitives.ReadUInt16BigEndian(body[offset..]));
        Assert.Equal(body.Length, offset + 2 + extensions.Length);
        var result = new List<(int, byte[])>();
        while (!extensions.IsEmpty)
        {
            var length = BinaryPrimitives.ReadUInt16BigEndian(extensions[2..]);
            result.Add((BinaryPrimitives.ReadUInt16BigEndian(extensions), extensions.Slice(4, length).ToArray()));
            extensions = extensions[(4 + length)..];
        }

        return result;
    }

    private sealed class CapturingStream : Stream
    {
        private readonly List<byte> _written = [];

        public byte[] Written => [.. _written];

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count) => _written.AddRange(buffer.AsSpan(offset, count));

        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("capture only");

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
