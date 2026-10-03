namespace Chameleon.Net.Profiles;

public static partial class BuiltInProfiles
{
    /// <summary>Mozilla Firefox 157.0 on GitHub Actions win25-vs2026 (image 20260925.250.1).
    /// <para>Captured 2026-10-03 by the Chameleon.Net Inspector's automated capture (eng/profile-capture), then reviewed.</para>
    /// <para>Expected JA4 <c>t13d1517h2_8daaf6152771_3cbfd9057e0d</c>, JA3 <c>9d42e90b0225e779f03141ddcd699df2</c>; Akamai <c>1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s</c>.</para>
    /// <para>From the capture:</para>
    /// <list type="bullet">
    /// <item>Seen: 4 TLS connection(s); Navigate over HTTP/2 (1), Fetch over HTTP/2 (2), WebSocket over HTTP/1.1 (3), Navigate over HTTP/1.1 (1), Fetch over HTTP/1.1 (1).</item>
    /// <item>GREASE ECH: AEADs and payload lengths are the ones seen over 4 connection(s); a client may pick from more.</item>
    /// </list>
    /// </summary>
    public static ClientProfile Firefox157Windows { get; } = new(
        Identity: new ProfileIdentity("firefox_157_windows", ClientPlatform.Windows, "Firefox", "157"),
        Tls: new TlsProfile(
            CipherSuites: [4865, 4867, 4866, 49195, 49199, 52393, 52392, 49196, 49200, 49171, 49172, 156, 157, 47, 53],
            Extensions:
            [
                new ServerNameExtension(),
                new ExtendedMasterSecretExtension(),
                new RenegotiationInfoExtension(),
                new SupportedGroupsExtension([0x11EC, 29, 23, 24, 25]),
                new EcPointFormatsExtension([0]),
                new SessionTicketExtension(),
                new AlpnExtension(["h2", "http/1.1"]),
                new StatusRequestExtension(),
                new DelegatedCredentialsExtension([0x0403, 0x0503, 0x0603, 0x0203]),
                new SignedCertificateTimestampExtension(),
                new KeyShareExtension([0x11EC, 29, 23]),
                new SupportedVersionsExtension([0x0304, 0x0303]),
                new SignatureAlgorithmsExtension([0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201]),
                new PskKeyExchangeModesExtension([1]),
                new RecordSizeLimitExtension(0x4001),
                new CompressCertificateExtension([1, 2, 3]),
                new EncryptedClientHelloGreaseExtension(AeadIds: [0x0001, 0x0003], PayloadLengths: [240, 336]),
            ],
            Shuffle: ExtensionShufflePolicy.None,
            Grease: GreasePlacement.None),
        Http2: new Http2Profile(
            Preface:
            [
                new Http2SettingsFrame([new Http2Setting(1, 65536), new Http2Setting(2, 0), new Http2Setting(4, 131072), new Http2Setting(5, 16384)]),
                new Http2WindowUpdateFrame(12517377),
            ],
            PseudoHeaderOrder: [PseudoHeader.Method, PseudoHeader.Path, PseudoHeader.Authority, PseudoHeader.Scheme],
            HeadersPriority: new Http2HeadersPriority(0, 21, false),
            HeadersPriorityOverrides: new Dictionary<RequestKind, Http2HeadersPriority>
            {
                [RequestKind.Navigate] = new Http2HeadersPriority(0, 41, false),
            },
            FirstStreamId: 3),
        Headers: new HeaderProfile(
            HeaderOrder:
            [
                "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer", "Connection", "Content-Type",
                "Content-Length", "Origin", "Cookie", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Priority", "TE",
            ],
            Overrides: new Dictionary<RequestKind, IReadOnlyList<string>>
            {
                [RequestKind.Navigate] =
                [
                    "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection", "Cookie",
                    "Upgrade-Insecure-Requests", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User", "Priority", "TE",
                ],
            },
            Http1Casing: HeaderCasing.AsSpecified,
            DefaultHeaders: new Dictionary<string, string>
            {
                ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0",
                ["Accept"] = "*/*",
                ["Accept-Language"] = "en-US,en;q=0.9",
                ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                ["Sec-Fetch-Dest"] = "empty",
                ["Sec-Fetch-Mode"] = "cors",
                ["Sec-Fetch-Site"] = "same-origin",
                ["Priority"] = "u=4",
                ["TE"] = "trailers",
                ["Connection"] = "keep-alive",
            },
            OrderMode: HeaderOrderMode.ProfileOrder,
            DefaultHeaderOverrides: new Dictionary<RequestKind, IReadOnlyDictionary<string, string>>
            {
                [RequestKind.Navigate] = new Dictionary<string, string>
                {
                    ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0",
                    ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    ["Accept-Language"] = "en-US,en;q=0.9",
                    ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                    ["Upgrade-Insecure-Requests"] = "1",
                    ["Sec-Fetch-Dest"] = "document",
                    ["Sec-Fetch-Mode"] = "navigate",
                    ["Sec-Fetch-Site"] = "none",
                    ["Sec-Fetch-User"] = "?1",
                    ["Priority"] = "u=0, i",
                    ["TE"] = "trailers",
                    ["Connection"] = "keep-alive",
                },
                [RequestKind.WebSocket] = new Dictionary<string, string>
                {
                    ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:157.0) Gecko/20100101 Firefox/157.0",
                    ["Accept"] = "*/*",
                    ["Accept-Language"] = "en-US,en;q=0.9",
                    ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                    ["Sec-Fetch-Dest"] = "empty",
                    ["Sec-Fetch-Mode"] = "websocket",
                    ["Sec-Fetch-Site"] = "same-origin",
                    ["Pragma"] = "no-cache",
                    ["Cache-Control"] = "no-cache",
                },
            },
            Http2OnlyHeaders: ["TE"]),
        WebSocket: new WebSocketProfile(
            HandshakeHeaderOrder:
            [
                "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Sec-WebSocket-Version", "Origin",
                "Sec-WebSocket-Extensions", "Sec-WebSocket-Key", "Connection", "Cookie", "Sec-Fetch-Dest", "Sec-Fetch-Mode",
                "Sec-Fetch-Site", "Pragma", "Cache-Control", "Upgrade",
            ],
            PerMessageDeflateOffer: "permessage-deflate",
            Alpn: ["http/1.1"]));
}
