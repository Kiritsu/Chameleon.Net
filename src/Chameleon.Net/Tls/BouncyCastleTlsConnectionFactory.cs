using System.Net;
using System.Runtime.ExceptionServices;
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

    /// <summary>Offer TLS 1.3 session tickets from earlier connections to the same host, as BoringSSL-based clients (Chrome, OkHttp on
    /// Conscrypt) do. Only for profiles that list psk_key_exchange_modes. On by default.</summary>
    public bool ResumeSessions { get; init; } = true;

    /// <summary>Where tickets are kept. Share one instance between factories to let their connections resume each other's sessions.</summary>
    public TlsSessionCache SessionCache { get; init => field = value ?? throw new ArgumentNullException(nameof(value)); } = new();

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

        var ticket = ResumeSessions && profile.Extensions.OfType<PskKeyExchangeModesExtension>().Any() ? SessionCache.Take(host, port, profile, _certificateValidator) : null;
        try
        {
            return await HandshakeAsync(transport, host, port, profile, ticket, cancellationToken).ConfigureAwait(false);
        }
        catch (TicketRejectedException rejected)
        {
            // A server that rejects the ticket should fall back to a full handshake; one that aborts before its ServerHello instead gets a
            // fresh connection without it. Failures after the ServerHello (certificate, handshake errors) aren't the ticket's doing.
            if (cancellationToken.IsCancellationRequested)
            {
                ExceptionDispatchInfo.Throw(rejected.InnerException!);
            }

            return await HandshakeAsync(transport, host, port, profile, ticket: null, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<TlsConnection> HandshakeAsync(
        ITransport transport, string host, int port, TlsProfile profile, SessionTicket? ticket, CancellationToken cancellationToken)
    {
        var stream = await transport.ConnectAsync(new DnsEndPoint(host, port), cancellationToken).ConfigureAwait(false);
        ChameleonTlsClientProtocol? protocol = null;
        try
        {
            Action<SessionTicket>? onTicket = ResumeSessions ? received => SessionCache.Add(host, port, profile, _certificateValidator, received) : null;
            // One set of GREASE values and one extension order per connection, so a retried ClientHello (after HelloRetryRequest) matches the first.
            var encoder = _encoder is ClientHelloEncoder shared ? shared.ForConnection() : _encoder;
            protocol = new ChameleonTlsClientProtocol(profile, encoder, ticket, onTicket);
            var client = _clientFactory.Create(profile, host, new BcTlsCrypto(_random), _certificateValidator);
            if (client is ProfileTlsClient profileClient)
            {
                profileClient.Resumption = ticket;
            }

            // The handshake's socket reads honour the token; disposing the stream also covers transports that ignore it.
            await using var abort = cancellationToken.Register(static state => ((Stream)state!).Dispose(), stream).ConfigureAwait(false);
            var tls = new NonBlockingTlsStream(protocol, stream);
            await tls.HandshakeAsync(client, cancellationToken).ConfigureAwait(false);

            return new TlsConnection(tls, protocol.NegotiatedApplicationProtocol, protocol.SessionResumed);
        }
        catch (Exception exception)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            if (ticket is not null && exception is IOException && protocol is { ServerHelloReceived: false })
            {
                throw new TicketRejectedException(exception);
            }

            throw;
        }
    }

    /// <summary>A handshake that offered a ticket failed before the server's first answer.</summary>
    private sealed class TicketRejectedException(Exception inner) : IOException(inner.Message, inner);
}
