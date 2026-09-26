using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Chameleon.Net.Profiles;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;

namespace Chameleon.Net.Tls;

/// <summary>Supplies ClientHello content to BouncyCastle from a <see cref="TlsProfile"/>. Wire order is not decided here.</summary>
internal sealed class ProfileTlsClient : DefaultTlsClient
{
    private readonly TlsProfile _profile;
    private readonly string _serverName;
    private readonly IServerCertificateValidator _certificateValidator;

    public ProfileTlsClient(TlsCrypto crypto, TlsProfile profile, string serverName, IServerCertificateValidator certificateValidator)
        : base(crypto)
    {
        _profile = profile;
        _serverName = serverName;
        _certificateValidator = certificateValidator;
    }

    /// <summary>A ticket from an earlier connection to offer as a resumption PSK. BouncyCastle only knows external PSKs; the key schedule is
    /// the same, and <see cref="ChameleonTlsClientProtocol"/> rewrites the identity's age and computes the binder with the resumption label.</summary>
    public SessionTicket? Resumption { get; set; }

    public override IList<TlsPskExternal>? GetExternalPsks() =>
        Resumption is { } ticket ? [new BasicTlsPskExternal(ticket.Identity, Crypto.CreateSecret(ticket.Psk), ticket.PrfAlgorithm)] : null;

    public override short[] GetPskKeyExchangeModes() =>
        Find<PskKeyExchangeModesExtension>()?.Modes.Select(static mode => (short)mode).ToArray() ?? base.GetPskKeyExchangeModes();

    public override TlsAuthentication GetAuthentication() => new ValidatingAuthentication(_certificateValidator, _serverName);

    public override int[] GetCipherSuites() => _profile.CipherSuites.Select(static suite => (int)suite).ToArray();

    protected override ProtocolVersion[] GetSupportedVersions()
    {
        var versions = Find<SupportedVersionsExtension>()?.Versions;
        if (versions is null)
        {
            return ProtocolVersion.TLSv12.Only();
        }

        return versions
            .Select(static version => version switch
            {
                0x0304 => ProtocolVersion.TLSv13,
                0x0303 => ProtocolVersion.TLSv12,
                0x0302 => ProtocolVersion.TLSv11,
                0x0301 => ProtocolVersion.TLSv10,
                _ => null,
            })
            .OfType<ProtocolVersion>()
            .ToArray();
    }

    protected override int[] GetSupportedGroups(IList<int> namedGroupRoles) =>
        Find<SupportedGroupsExtension>()?.Groups.Select(static group => (int)group).ToArray() ?? [];

    // Hybrid post-quantum shares are added by ChameleonTlsClientProtocol; BouncyCastle can't generate them.
    public override IList<int> GetEarlyKeyShareGroups() =>
        Find<KeyShareExtension>()?.Groups.Select(static group => (int)group).Where(static group => !HybridKeyAgreement.IsHybrid(group)).ToList() ?? [];

    protected override IList<SignatureAndHashAlgorithm> GetSupportedSignatureAlgorithms() =>
        Find<SignatureAlgorithmsExtension>()?.Schemes
            .Select(static scheme => new SignatureAndHashAlgorithm((short)(scheme >> 8), (short)(scheme & 0xFF)))
            .ToList() ?? [];

    protected override IList<SignatureAndHashAlgorithm>? GetSupportedSignatureAlgorithmsCert() => null;

    public override bool ShouldUseExtendedMasterSecret() => Find<ExtendedMasterSecretExtension>() is not null;

    public override IDictionary<int, byte[]> GetClientExtensions()
    {
        var extensions = new Dictionary<int, byte[]>();

        foreach (var extension in _profile.Extensions)
        {
            switch (extension)
            {
                // RFC 6066 forbids IP literals in SNI; BoringSSL, Conscrypt and browsers leave the extension out.
                case ServerNameExtension when !System.Net.IPAddress.TryParse(_serverName, out _):
                    TlsExtensionsUtilities.AddServerNameExtensionClient(extensions,
                        [new ServerName(NameType.host_name, Encoding.ASCII.GetBytes(_serverName))]);
                    break;
                case ServerNameExtension:
                    break;
                case StatusRequestExtension:
                    extensions[ExtensionType.status_request] = [(byte)CertificateStatusType.ocsp, 0, 0, 0, 0];
                    break;
                case SupportedGroupsExtension groups:
                    m_supportedGroups = groups.Groups.Select(static group => (int)group).ToList();
                    TlsExtensionsUtilities.AddSupportedGroupsExtension(extensions, m_supportedGroups);
                    break;
                case EcPointFormatsExtension formats:
                    TlsExtensionsUtilities.AddSupportedPointFormatsExtension(extensions,
                        formats.Formats.Select(static format => (short)format).ToArray());
                    break;
                case SignatureAlgorithmsExtension:
                    TlsExtensionsUtilities.AddSignatureAlgorithmsExtension(extensions, GetSupportedSignatureAlgorithms());
                    break;
                case AlpnExtension alpn:
                    TlsExtensionsUtilities.AddAlpnExtensionClient(extensions,
                        alpn.Protocols.Select(ProtocolName.AsUtf8Encoding).ToList());
                    break;
                case SignedCertificateTimestampExtension:
                    extensions[ExtensionType.signed_certificate_timestamp] = TlsUtilities.EmptyBytes;
                    break;
                case ExtendedMasterSecretExtension:
                    extensions[ExtensionType.extended_master_secret] = TlsUtilities.EmptyBytes;
                    break;
                case CompressCertificateExtension compress:
                    TlsExtensionsUtilities.AddCompressCertificateExtension(extensions,
                        compress.Algorithms.Select(static algorithm => (int)algorithm).ToArray());
                    break;
                case RecordSizeLimitExtension limit:
                    TlsExtensionsUtilities.AddRecordSizeLimitExtension(extensions, limit.Limit);
                    break;
                case DelegatedCredentialsExtension delegated:
                    extensions[delegated.Type] = EncodeUint16List(delegated.Schemes);
                    break;
                case SessionTicketExtension:
                    extensions[ExtensionType.session_ticket] = TlsUtilities.EmptyBytes;
                    break;
                case PskKeyExchangeModesExtension modes:
                    TlsExtensionsUtilities.AddPskKeyExchangeModesExtension(extensions,
                        modes.Modes.Select(static mode => (short)mode).ToArray());
                    break;
                case ApplicationSettingsExtension alps:
                    extensions[alps.Type] = EncodeAlps(alps.Protocols);
                    break;
                case EncryptedClientHelloGreaseExtension ech:
                    extensions[ech.Type] = EncodeGreaseEch(ech);
                    break;
                case RenegotiationInfoExtension:
                    extensions[ExtensionType.renegotiation_info] = [0];
                    break;
                case RawExtension raw:
                    extensions[raw.Type] = raw.Body.ToArray();
                    break;
                case SupportedVersionsExtension:
                case KeyShareExtension:
                case PaddingExtension:
                case GreaseExtension:
                    break;
                default:
                    throw new NotSupportedException($"Extension {extension.GetType().Name} is not supported.");
            }
        }

        return extensions;
    }

    private T? Find<T>() where T : TlsExtension => _profile.Extensions.OfType<T>().FirstOrDefault();

    private static byte[] EncodeUint16List(IReadOnlyList<ushort> values)
    {
        var body = new byte[2 + values.Count * 2];
        TlsUtilities.WriteUint16(values.Count * 2, body, 0);
        for (var i = 0; i < values.Count; i++)
        {
            TlsUtilities.WriteUint16(values[i], body, 2 + i * 2);
        }

        return body;
    }

    private static byte[] EncodeAlps(IReadOnlyList<string> protocols)
    {
        using var list = new MemoryStream();
        foreach (var protocol in protocols)
        {
            TlsUtilities.WriteOpaque8(Encoding.ASCII.GetBytes(protocol), list);
        }

        using var body = new MemoryStream();
        TlsUtilities.WriteOpaque16(list.ToArray(), body);
        return body.ToArray();
    }

    // Shape of GREASE ECH (draft-ietf-tls-esni): outer type, HKDF-SHA256 and an AEAD, random config id, 32-byte enc, random payload.
    // BoringSSL picks the payload length as 32 * {4..7} + 16 bytes of AEAD overhead, i.e. 144, 176, 208 or 240, always with AES-128-GCM.
    private byte[] EncodeGreaseEch(EncryptedClientHelloGreaseExtension ech)
    {
        var random = Crypto.SecureRandom;
        var aead = ech.AeadIds is { Count: > 0 } aeads ? aeads[random.Next(aeads.Count)] : (ushort)0x0001;
        var enc = new byte[32];
        var payload = new byte[ech.PayloadLengths is { Count: > 0 } lengths ? lengths[random.Next(lengths.Count)] : (32 * (4 + random.Next(4))) + 16];
        random.NextBytes(enc);
        random.NextBytes(payload);

        using var body = new MemoryStream();
        body.WriteByte(0);
        TlsUtilities.WriteUint16(0x0001, body);
        TlsUtilities.WriteUint16(aead, body);
        body.WriteByte((byte)random.Next(256));
        TlsUtilities.WriteOpaque16(enc, body);
        TlsUtilities.WriteOpaque16(payload, body);
        return body.ToArray();
    }

    private sealed class ValidatingAuthentication : TlsAuthentication
    {
        private readonly IServerCertificateValidator _validator;
        private readonly string _targetHost;

        public ValidatingAuthentication(IServerCertificateValidator validator, string targetHost)
        {
            _validator = validator;
            _targetHost = targetHost;
        }

        public TlsCredentials? GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null;

        public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
        {
            var chain = new X509Certificate2Collection();
            foreach (var certificate in serverCertificate.Certificate.GetCertificateList())
            {
                chain.Add(X509CertificateLoader.LoadCertificate(certificate.GetEncoded()));
            }

            try
            {
                _validator.Validate(chain, _targetHost);
            }
            catch (AuthenticationException exception)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate, exception);
            }
            finally
            {
                foreach (var certificate in chain)
                {
                    certificate.Dispose();
                }
            }
        }
    }
}
