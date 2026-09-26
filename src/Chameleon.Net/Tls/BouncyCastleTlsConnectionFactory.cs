using System.Net;
using Chameleon.Net.Profiles;
using Chameleon.Net.Transport;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace Chameleon.Net.Tls;

public sealed class BouncyCastleTlsConnectionFactory : ITlsConnectionFactory
{
    private readonly ITlsClientFactory _clientFactory;
    private readonly IClientHelloEncoder _encoder;
    private readonly IServerCertificateValidator _certificateValidator;
    private readonly SecureRandom _random;

    /// <summary>Profile-driven client hello, OS trust store validation.</summary>
    public BouncyCastleTlsConnectionFactory()
        : this(new SecureRandom())
    {
    }

    private BouncyCastleTlsConnectionFactory(SecureRandom random)
        : this(new ProfileTlsClientFactory(), new ClientHelloEncoder(random), new SystemCertificateValidator(), random)
    {
    }

    public BouncyCastleTlsConnectionFactory(
        ITlsClientFactory clientFactory,
        IClientHelloEncoder encoder,
        IServerCertificateValidator certificateValidator,
        SecureRandom random)
    {
        ArgumentNullException.ThrowIfNull(clientFactory);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(certificateValidator);
        ArgumentNullException.ThrowIfNull(random);

        _clientFactory = clientFactory;
        _encoder = encoder;
        _certificateValidator = certificateValidator;
        _random = random;
    }

    public async Task<TlsConnection> ConnectAsync(ITransport transport, string host, int port, TlsProfile profile, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentException.ThrowIfNullOrEmpty(host);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(port);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, IPEndPoint.MaxPort);
        ArgumentNullException.ThrowIfNull(profile);

        var stream = await transport.ConnectAsync(new DnsEndPoint(host, port), cancellationToken).ConfigureAwait(false);
        try
        {
            var protocol = new ChameleonTlsClientProtocol(stream, profile, _encoder);
            var client = _clientFactory.Create(profile, host, new BcTlsCrypto(_random), _certificateValidator);

            // BouncyCastle's handshake is synchronous over the stream; disposing the stream is the only way to abort it.
            await using var abort = cancellationToken.Register(static state => ((Stream)state!).Dispose(), stream).ConfigureAwait(false);
            await Task.Run(() => protocol.Connect(client), cancellationToken).ConfigureAwait(false);

            return new TlsConnection(new DuplexTlsStream(protocol.Stream, stream), protocol.NegotiatedApplicationProtocol);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
