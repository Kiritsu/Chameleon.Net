using System.Buffers.Binary;
using System.Net;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.Tls;
using Chameleon.Net.Transport;
using Microsoft.AspNetCore.Builder;
using Org.BouncyCastle.Security;

namespace Chameleon.Net.Tests.Tls;

/// <summary>A server that doesn't support the only key share offered answers with HelloRetryRequest; the second ClientHello must
/// match the first apart from key_share and padding (RFC 8446 §4.1.2), GREASE values and shuffled order included.</summary>
public sealed class HelloRetryTests
{
    [Fact]
    public async Task RetriedClientHelloKeepsGreaseAndExtensionOrder()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        using var certificate = TestCertificates.SelfSigned();
        await using var server = await KestrelHttp2Server.StartAsync(static app => app.MapGet("/", static () => "ok"), certificate: certificate);

        // Only an X25519MLKEM768 share, which SChannel doesn't implement: it asks again for a classical group.
        var chromium = BuiltInProfiles.Chromium152Windows.Tls;
        var profile = chromium with
        {
            Extensions =
            [
                .. chromium.Extensions.Select(static extension => extension switch
                {
                    SupportedGroupsExtension => new SupportedGroupsExtension([0x11EC, 29, 23, 24]),
                    KeyShareExtension => new KeyShareExtension([0x11EC]),
                    _ => extension,
                }),
            ],
        };
        var transport = new RecordingTransport();
        var factory = new BouncyCastleTlsConnectionFactory(
            new ProfileTlsClientFactory(), new ClientHelloEncoder(new SecureRandom()), new TrustAnyCertificate(), new SecureRandom());

        var connection = await factory.ConnectAsync(transport, "127.0.0.1", server.Url("/").Port, profile, cancellationToken);
        await connection.Stream.DisposeAsync();

        var hellos = transport.ClientHellos();
        if (hellos.Count == 1)
        {
            // The retry depends on the server lacking ML-KEM (SChannel, OpenSSL < 3.5); a newer TLS stack takes the hybrid share directly.
            Assert.Skip("The local TLS server accepted X25519MLKEM768, so there was no HelloRetryRequest to test.");
        }

        Assert.Equal(2, hellos.Count);
        var (first, second) = (ClientHelloParser.Parse(hellos[0]), ClientHelloParser.Parse(hellos[1]));
        Assert.Equal(first.CipherSuites, second.CipherSuites);
        Assert.Equal(first.SupportedGroups, second.SupportedGroups);
        Assert.Equal(first.SupportedVersions, second.SupportedVersions);
        Assert.Equal(first.SignatureAlgorithms, second.SignatureAlgorithms);
        Assert.Equal(first.ExtensionTypes.Where(static t => t != 21), second.ExtensionTypes.Where(static t => t != 21));

        // key_share: GREASE + X25519MLKEM768 first, then only the one group the server asked for (no GREASE, as BoringSSL does).
        Assert.Equal([first.SupportedGroups[0], 0x11EC], KeyShareGroups(hellos[0]));
        Assert.Contains(Assert.Single(KeyShareGroups(hellos[1])), new ushort[] { 29, 23, 24 });
    }

    private static List<ushort> KeyShareGroups(byte[] record)
    {
        var body = record.AsSpan(5 + 4);
        var offset = 2 + 32;
        offset += 1 + body[offset];
        offset += 2 + BinaryPrimitives.ReadUInt16BigEndian(body[offset..]);
        offset += 1 + body[offset];
        var extensions = body.Slice(offset + 2, BinaryPrimitives.ReadUInt16BigEndian(body[offset..]));
        while (BinaryPrimitives.ReadUInt16BigEndian(extensions) != 51)
        {
            extensions = extensions[(4 + BinaryPrimitives.ReadUInt16BigEndian(extensions[2..]))..];
        }

        var shares = extensions[(4 + 2)..(4 + BinaryPrimitives.ReadUInt16BigEndian(extensions[2..]))];
        var groups = new List<ushort>();
        while (!shares.IsEmpty)
        {
            groups.Add(BinaryPrimitives.ReadUInt16BigEndian(shares));
            shares = shares[(4 + BinaryPrimitives.ReadUInt16BigEndian(shares[2..]))..];
        }

        return groups;
    }

    /// <summary>Records what the client writes and splits out the handshake records that carry a ClientHello.</summary>
    private sealed class RecordingTransport : ITransport
    {
        private readonly List<byte> _written = [];

        public async Task<Stream> ConnectAsync(DnsEndPoint endpoint, CancellationToken cancellationToken = default) =>
            new Recording(await new TcpTransport().ConnectAsync(endpoint, cancellationToken), _written);

        public List<byte[]> ClientHellos()
        {
            var bytes = _written.ToArray();
            var result = new List<byte[]>();
            for (var offset = 0; offset + 5 <= bytes.Length;)
            {
                var length = BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset + 3));
                if (bytes[offset] == 22 && bytes[offset + 5] == 1)
                {
                    result.Add(bytes[offset..(offset + 5 + length)]);
                }

                offset += 5 + length;
            }

            return result;
        }

        private sealed class Recording(Stream inner, List<byte> written) : Stream
        {
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => throw new NotSupportedException();
            public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

            public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);

            public override void Write(byte[] buffer, int offset, int count)
            {
                lock (written)
                {
                    written.AddRange(buffer.AsSpan(offset, count));
                }

                inner.Write(buffer, offset, count);
            }

            public override void Flush() => inner.Flush();

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    inner.Dispose();
                }

                base.Dispose(disposing);
            }
        }
    }
}
