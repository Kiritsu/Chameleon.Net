using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Chameleon.Net.Profiles;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace Chameleon.Net.Tls;

/// <summary>Lets BouncyCastle assemble the ClientHello and own the handshake state, but writes the message bytes itself so extension order survives.</summary>
internal sealed class ChameleonTlsClientProtocol : TlsClientProtocol
{
    private readonly TlsProfile _profile;
    private readonly IClientHelloEncoder _encoder;
    private readonly SessionTicket? _resumption;
    private readonly Action<SessionTicket>? _onTicket;
    private bool _initialHelloSent;
    private TlsSecret? _resumptionMasterSecret;

    public ChameleonTlsClientProtocol(Stream stream, TlsProfile profile, IClientHelloEncoder encoder)
        : this(stream, profile, encoder, resumption: null, onTicket: null)
    {
    }

    /// <param name="resumption">The ticket the TlsClient offers as its PSK (see <see cref="ProfileTlsClient.Resumption"/>).</param>
    /// <param name="onTicket">Receives each NewSessionTicket the server sends after the handshake, ready to offer on a later connection.</param>
    public ChameleonTlsClientProtocol(Stream stream, TlsProfile profile, IClientHelloEncoder encoder, SessionTicket? resumption, Action<SessionTicket>? onTicket)
        : base(stream)
    {
        _profile = profile;
        _encoder = encoder;
        _resumption = resumption;
        _onTicket = onTicket;
    }

    /// <summary>Non-blocking mode: no stream; <see cref="NonBlockingTlsStream"/> moves the bytes (OfferInput / ReadOutput).</summary>
    public ChameleonTlsClientProtocol(TlsProfile profile, IClientHelloEncoder encoder, SessionTicket? resumption, Action<SessionTicket>? onTicket)
    {
        _profile = profile;
        _encoder = encoder;
        _resumption = resumption;
        _onTicket = onTicket;
    }

    public string? NegotiatedApplicationProtocol => Context.SecurityParameters.ApplicationProtocol?.GetUtf8Decoding();

    /// <summary>Whether the server accepted the offered ticket (no certificate was exchanged).</summary>
    public bool SessionResumed { get; private set; }

    /// <summary>Whether a ServerHello (or HelloRetryRequest) arrived: a handshake that failed before it may have been rejected over the ticket.</summary>
    public bool ServerHelloReceived { get; private set; }

    protected override ServerHello ReceiveServerHelloMessage(MemoryStream buf)
    {
        ServerHelloReceived = true;
        return base.ReceiveServerHelloMessage(buf);
    }

    protected override void SendClientHelloMessage()
    {
        var afterRetry = _initialHelloSent;
        if (!_initialHelloSent)
        {
            // Not after a HelloRetryRequest: BouncyCastle has then already narrowed key_share to the server's pick.
            AddHybridKeyShares();
            _initialHelloSent = true;
        }

        // BouncyCastle wrote an external-PSK identity (age 0) and will append "ext binder" binders; a ticket needs its real obfuscated age
        // and the "res binder" label, and pre_shared_key must be the last extension of the bytes actually sent.
        var offersTicket = _resumption is not null && m_clientHello.Extensions.ContainsKey(ExtensionType.pre_shared_key);
        if (offersTicket)
        {
            m_clientHello.Extensions[ExtensionType.pre_shared_key] = Tls13Resumption.PreSharedKeyBody(_resumption!);
        }

        var encoded = _encoder.Encode(m_clientHello, _profile);
        var message = MemoryMarshal.TryGetArray(encoded, out var segment) && segment.Offset == 0 && segment.Count == segment.Array!.Length
            ? segment.Array
            : encoded.ToArray();

        if (offersTicket)
        {
            WriteBinder(message, afterRetry);
        }

        HandshakeHash(this).Update(message, 0, message.Length);
        SafeWriteRecord(ContentType.handshake, message, 0, message.Length);
    }

    // The binder covers the ClientHello up to (not including) the binders list, prefixed after a HelloRetryRequest by the transcript so far.
    private void WriteBinder(byte[] message, bool afterRetry)
    {
        var ticket = _resumption!;
        var hashLength = ticket.HashLength;
        var truncatedLength = message.Length - (2 + 1 + hashLength);

        var transcript = afterRetry ? HandshakeHash(this).ForkPrfHash() : Context.Crypto.CreateHash(ticket.CryptoHashAlgorithm);
        transcript.Update(message, 0, truncatedLength);
        var binder = Tls13Resumption.Binder(Context.Crypto, ticket.Psk, ticket.CryptoHashAlgorithm, transcript.CalculateHash());
        binder.CopyTo(message, message.Length - hashLength);
    }

    /// <summary>resumption_master_secret needs the transcript through the client Finished, which only exists right after it is sent.</summary>
    protected override void Send13FinishedMessage()
    {
        SendClientEncryptedExtensions();
        base.Send13FinishedMessage();

        // BouncyCastle clears m_selectedPsk13 when it cleans up after the handshake.
        SessionResumed = m_selectedPsk13;

        if (_onTicket is not null)
        {
            var parameters = Context.SecurityParameters;
            _resumptionMasterSecret = Tls13Resumption.ResumptionMasterSecret(
                parameters.MasterSecret, parameters.PrfCryptoHashAlgorithm, HandshakeHash(this).ForkPrfHash().CalculateHash());
        }
    }

    /// <summary>BouncyCastle discards TLS 1.3 tickets; keep them, with the PSK derived while the resumption master secret is known.</summary>
    protected override void Receive13NewSessionTicket(MemoryStream buf)
    {
        if (IsHandshaking)
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        var lifetime = TlsUtilities.ReadUint32(buf);
        var ageAdd = TlsUtilities.ReadUint32(buf);
        var nonce = TlsUtilities.ReadOpaque8(buf);
        var identity = TlsUtilities.ReadOpaque16(buf, 1);
        TlsUtilities.ReadOpaque16(buf);
        if (buf.Position < buf.Length)
        {
            throw new TlsFatalAlert(AlertDescription.decode_error);
        }

        if (_onTicket is null || _resumptionMasterSecret is null || lifetime == 0)
        {
            return;
        }

        var parameters = Context.SecurityParameters;
        var algorithm = parameters.PrfCryptoHashAlgorithm;
        _onTicket(new SessionTicket(
            identity,
            Tls13Resumption.TicketPsk(_resumptionMasterSecret, algorithm, nonce),
            parameters.PrfAlgorithm,
            algorithm,
            (uint)ageAdd,
            Stopwatch.GetTimestamp(),
            TimeSpan.FromSeconds(Math.Min(lifetime, SessionTicket.MaxLifetime.TotalSeconds))));
    }

    /// <summary>BouncyCastle doesn't know CompressedCertificate (RFC 8879): decompress it and run BouncyCastle's own certificate processing.
    /// The transcript covers the compressed form, which BouncyCastle has already hashed by the time this runs.</summary>
    protected override void Handle13HandshakeMessage(short type, HandshakeMessageInput buf)
    {
        if (type != HandshakeType.compressed_certificate)
        {
            base.Handle13HandshakeMessage(type, buf);
            return;
        }

        var offered = _profile.Extensions.OfType<CompressCertificateExtension>().FirstOrDefault()?.Algorithms;
        if (offered is null || m_connectionState is not (CS_SERVER_ENCRYPTED_EXTENSIONS or CS_SERVER_CERTIFICATE_REQUEST))
        {
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }

        if (m_connectionState != CS_SERVER_CERTIFICATE_REQUEST)
        {
            Skip13CertificateRequest();
        }

        // No UpdateHash here: TlsProtocol.ProcessHandshakeQueue already hashed the compressed message, as RFC 8879 requires.
        var body = new byte[buf.Length - buf.Position];
        buf.ReadExactly(body);
        using var certificate = new MemoryStream(CertificateCompression.Decompress(body, offered));
        Receive13ServerCertificate(certificate);
        m_connectionState = CS_SERVER_CERTIFICATE;
    }

    /// <summary>When the server accepted ALPS (application_settings) in EncryptedExtensions, the client must answer with its own settings in a
    /// ClientEncryptedExtensions message before Finished; BouncyCastle doesn't know either, and servers like Google abort without it.</summary>
    private void SendClientEncryptedExtensions()
    {
        var alps = _profile.Extensions.OfType<ApplicationSettingsExtension>().FirstOrDefault();
        if (alps is not null && m_serverExtensions is not null && m_serverExtensions.ContainsKey(alps.Type))
        {
            var message = ApplicationSettings.ClientEncryptedExtensions(alps.Type);
            HandshakeHash(this).Update(message, 0, message.Length);
            SafeWriteRecord(ContentType.handshake, message, 0, message.Length);
        }
    }

    /// <summary>BouncyCastle has no hybrid post-quantum groups: generate their shares here, register the agreements where BouncyCastle
    /// looks them up when the ServerHello arrives, and rebuild key_share in the profile's order.</summary>
    private void AddHybridKeyShares()
    {
        if (_profile.Extensions.OfType<KeyShareExtension>().FirstOrDefault() is not { } keyShare
            || !keyShare.Groups.Any(static group => HybridKeyAgreement.IsHybrid(group))
            || !m_clientHello.Extensions.TryGetValue(ExtensionType.key_share, out var produced))
        {
            return;
        }

        var shares = TlsExtensionsUtilities.ReadKeyShareClientHello(produced)
            .ToDictionary(static entry => entry.NamedGroup, static entry => entry.KeyExchange);
        foreach (var group in keyShare.Groups.Where(static group => HybridKeyAgreement.IsHybrid(group)))
        {
            var agreement = HybridKeyAgreement.Create(Context.Crypto, group);
            m_clientAgreements[group] = agreement;
            shares[group] = agreement.GenerateEphemeral();
        }

        var ordered = keyShare.Groups
            .Where(group => shares.ContainsKey(group))
            .Select(group => new KeyShareEntry(group, shares[group]))
            .ToList();
        m_clientHello.Extensions[ExtensionType.key_share] = TlsExtensionsUtilities.CreateKeyShareClientHello(ordered);
    }

    // BouncyCastle's writer reorders extensions (empty bodies first) and the transcript hash is internal; this is the one seam it does not expose.
    // Pinned by BouncyCastleInternalsTests: a BouncyCastle upgrade that renames it fails there, not at handshake time.
    [UnsafeAccessor(UnsafeAccessorKind.Field, Name = "m_handshakeHash")]
    private static extern ref TlsHandshakeHash HandshakeHash(TlsProtocol protocol);
}
