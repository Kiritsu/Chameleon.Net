namespace Chameleon.Net.Profiles;

public static partial class BuiltInProfiles
{
    /// <summary>Firefox 156 on Windows (NSS, Necko's HTTP/2 and header logic).
    /// <para>Captured 2026-09-26 from Firefox 156.0.1 (headless, fresh profile, driven over WebDriver BiDi): TLS and HTTP/2 via
    /// tls.peet.ws on three separate launches, HTTP/1.1, fetch()/POST, cookies and the WebSocket handshake via a local capture server.
    /// Nothing adjusted by hand.</para>
    /// <para>Unlike Chrome, NSS neither shuffles extensions nor sends GREASE, so JA3 is stable too: JA3 <c>9d42e90b0225e779f03141ddcd699df2</c>,
    /// JA4 <c>t13d1517h2_8daaf6152771_3cbfd9057e0d</c>. Akamai <c>1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s</c>; the first request
    /// uses stream 3, with HEADERS priority weight 42 (navigation) or 22 (fetch), never exclusive.</para>
    /// <para>Differences from the real client: compress_certificate offers zstd like Firefox does, but a server that picks it fails the
    /// handshake (no zstd decoder yet); a server-sent delegated credential isn't supported; response bodies a server sends
    /// zstd-encoded are returned undecoded. The HPACK encoder follows OkHttp's indexing, not Firefox's.</para></summary>
    public static ClientProfile Firefox156Windows { get; } = new(
        Identity: new ProfileIdentity("firefox_156_windows", ClientPlatform.Windows, "Firefox", "156"),
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
                // NSS: HKDF-SHA256 with AES-128-GCM or ChaCha20-Poly1305, always a 240-byte payload.
                new EncryptedClientHelloGreaseExtension(AeadIds: [0x0001, 0x0003], PayloadLengths: [240]),
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
            // Weight 22 (wire 21) for fetch(), 42 (wire 41) for navigations; on stream 0, not exclusive.
            HeadersPriority: new Http2HeadersPriority(0, 21, false),
            HeadersPriorityOverrides: new Dictionary<RequestKind, Http2HeadersPriority>
            {
                [RequestKind.Navigate] = new(0, 41, false),
            },
            FirstStreamId: 3),
        Headers: new HeaderProfile(
            HeaderOrder:
            [
                "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer", "Content-Type", "Content-Length", "Origin", "Connection",
                "Cookie", "Upgrade-Insecure-Requests", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User", "Priority", "Pragma",
                "Cache-Control", "TE",
            ],
            Overrides: new Dictionary<RequestKind, IReadOnlyList<string>>(),
            Http1Casing: HeaderCasing.AsSpecified,
            DefaultHeaders: new Dictionary<string, string>
            {
                ["User-Agent"] = FirefoxUserAgent,
                ["Accept"] = "*/*",
                ["Accept-Language"] = "en-US,en;q=0.9",
                ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                ["Connection"] = "keep-alive",
                ["Sec-Fetch-Dest"] = "empty",
                ["Sec-Fetch-Mode"] = "cors",
                ["Sec-Fetch-Site"] = "same-origin",
                ["Priority"] = "u=4",
                ["TE"] = "trailers",
            },
            OrderMode: HeaderOrderMode.ProfileOrder,
            DefaultHeaderOverrides: new Dictionary<RequestKind, IReadOnlyDictionary<string, string>>
            {
                [RequestKind.Navigate] = new Dictionary<string, string>
                {
                    ["User-Agent"] = FirefoxUserAgent,
                    ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    ["Accept-Language"] = "en-US,en;q=0.9",
                    ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                    ["Connection"] = "keep-alive",
                    ["Upgrade-Insecure-Requests"] = "1",
                    ["Sec-Fetch-Dest"] = "document",
                    ["Sec-Fetch-Mode"] = "navigate",
                    ["Sec-Fetch-Site"] = "none",
                    ["Sec-Fetch-User"] = "?1",
                    ["Priority"] = "u=0, i",
                    ["TE"] = "trailers",
                },
                [RequestKind.WebSocket] = new Dictionary<string, string>
                {
                    ["User-Agent"] = FirefoxUserAgent,
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
            // Firefox sends "te: trailers" only over HTTP/2; Priority goes out on HTTP/1.1 too.
            Http2OnlyHeaders: ["TE"]),
        WebSocket: new WebSocketProfile(
            HandshakeHeaderOrder:
            [
                "Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Sec-WebSocket-Version", "Origin", "Sec-WebSocket-Extensions",
                "Sec-WebSocket-Key", "Connection", "Cookie", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Pragma", "Cache-Control", "Upgrade",
            ],
            PerMessageDeflateOffer: "permessage-deflate",
            Alpn: ["http/1.1"]));

    private const string FirefoxUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0";
}
