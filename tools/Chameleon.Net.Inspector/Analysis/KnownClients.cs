using System.Net;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Tls;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;

namespace Chameleon.Net.Inspector.Analysis;

/// <summary>The built-in profiles' TLS and HTTP/2 signatures, computed by running each profile's real handshake into a capturing transport.</summary>
internal sealed class KnownClients
{
    private KnownClients(IReadOnlyList<KnownClient> clients) => Clients = clients;

    public IReadOnlyList<KnownClient> Clients { get; }

    public static async Task<KnownClients> CreateAsync(IEnumerable<ClientProfile>? profiles = null)
    {
        profiles ??= [BuiltInProfiles.OkHttp4Android13, BuiltInProfiles.Chromium152Windows, BuiltInProfiles.Edge153Windows, BuiltInProfiles.Firefox156Windows];
        var clients = new List<KnownClient>();
        foreach (var profile in profiles)
        {
            var hello = ClientHelloDetails.Parse(await CaptureHandshakeAsync(profile.Tls));
            clients.Add(new KnownClient(profile, FamilyOf(profile), TlsKey(hello), AkamaiFingerprint.Compute(profile.Http2)));
        }

        return new KnownClients(clients);
    }

    public static ClientFamily FamilyOf(ClientProfile profile) => profile.Identity.ClientFamily switch
    {
        "Chromium" or "Edge" or "Chrome" => ClientFamily.Chromium,
        "Firefox" => ClientFamily.Firefox,
        "Safari" => ClientFamily.Safari,
        "OkHttp" => ClientFamily.OkHttp,
        _ => ClientFamily.Unknown,
    };

    /// <summary>JA4's sorted cipher and extension sets plus signature algorithms, leaving out what changes between connections of one client:
    /// SNI and ALPN (per target), padding (sized to the hello), pre_shared_key and early_data (resumption).</summary>
    public static string TlsKey(ClientHelloDetails hello)
    {
        ushort[] variable = [ClientHelloDetails.ServerNameType, ClientHelloDetails.AlpnType, ClientHelloDetails.PaddingType,
            ClientHelloDetails.PreSharedKeyType, ClientHelloDetails.EarlyDataType];
        var ciphers = hello.CipherSuites.Where(static c => !TlsNames.IsGrease(c)).Order();
        var extensions = hello.ExtensionTypes.Where(e => !TlsNames.IsGrease(e) && !variable.Contains(e)).Order();
        var signatures = hello.SignatureAlgorithms.Where(static s => !TlsNames.IsGrease(s));
        return $"{string.Join(',', ciphers)}_{string.Join(',', extensions)}_{string.Join(',', signatures)}";
    }

    public IReadOnlyList<KnownClient> MatchTls(ClientHelloDetails hello)
    {
        var key = TlsKey(hello);
        return [.. Clients.Where(c => c.TlsKey == key)];
    }

    public IReadOnlyList<KnownClient> MatchHttp2(string akamai) => [.. Clients.Where(c => c.Akamai == akamai)];

    private static async Task<byte[]> CaptureHandshakeAsync(TlsProfile profile)
    {
        var transport = new CapturingTransport();
        try
        {
            await new BouncyCastleTlsConnectionFactory().ConnectAsync(transport, "example.com", 443, profile);
        }
        catch (IOException)
        {
            // Expected: the capturing transport has no server behind it.
        }

        return transport.Written.AsSpan(5).ToArray();
    }

    private sealed class CapturingTransport : ITransport
    {
        private readonly List<byte> _written = [];

        public byte[] Written => [.. _written];

        public Task<Stream> ConnectAsync(DnsEndPoint endpoint, CancellationToken cancellationToken = default) =>
            Task.FromResult<Stream>(new CaptureStream(_written));
    }

    private sealed class CaptureStream(List<byte> written) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override void Write(byte[] buffer, int offset, int count) => written.AddRange(buffer.AsSpan(offset, count));

        public override int Read(byte[] buffer, int offset, int count) => throw new IOException("No server.");

        public override void Flush()
        {
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
    }
}

internal sealed record KnownClient(ClientProfile Profile, ClientFamily Family, string TlsKey, string Akamai)
{
    public string Name => Profile.Identity.Name;
}
