namespace Chameleon.Net.Profiles;

public static partial class BuiltInProfiles
{
    /// <summary>Chromium 152 on Windows (BoringSSL, Chromium's HTTP/2 and header logic).
    /// <para>Captured 2026-09-26 from Chromium 152.0.7977.130 embedded in a Windows desktop app: TLS and HTTP/2 via tls.peet.ws,
    /// HTTP/1.1 and the WebSocket handshake via a local capture server. Adjusted: the app's User-Agent tokens were removed and
    /// Accept-Language made generic. The embedded navigation sent no client hints, and none are sent here. Where client hints and
    /// Cookie go in the order was first taken from Chrome's known order, then confirmed on Edge 153 (same network stack; see
    /// <see cref="Edge153Windows"/>).</para>
    /// <para>Expected JA4 <c>t13d1516h2_8daaf6152771_806a8c22fdea</c> (JA3 changes per connection: extension shuffle);
    /// Akamai <c>1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p</c>.</para>
    /// <para>Resumed connections carry pre_shared_key and show <c>t13d1517h2_8daaf6152771_a87ad97598a9</c>, as the browser's do.</para>
    /// <para>Differences from the real client: bodies a server sends zstd-encoded are returned undecoded, with Content-Encoding kept.</para></summary>
    public static ClientProfile Chromium152Windows { get; } = new(
        Identity: new ProfileIdentity("chromium_152_windows", ClientPlatform.Windows, "Chromium", "152"),
        Tls: ChromiumFamilyTls(),
        Http2: ChromiumFamilyHttp2(),
        Headers: ChromiumFamilyHeaders(ChromiumUserAgent, "\"Not?A_Brand\";v=\"24\", \"Chromium\";v=\"152\"", navigationClientHints: false),
        WebSocket: ChromiumFamilyWebSocket());

    private const string ChromiumUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";

    // Chromium 152 and Edge 153 on Windows share every layer below the brand strings: identical JA4, Akamai and header order.
    // Builders rather than shared instances: static initializers in different files of a partial class run in no guaranteed order.
    private static TlsProfile ChromiumFamilyTls() => new(
        CipherSuites: [4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
        Extensions:
        [
            new GreaseExtension(),
            new SupportedVersionsExtension([0x0304, 0x0303]),
            new PskKeyExchangeModesExtension([1]),
            new SessionTicketExtension(),
            new AlpnExtension(["h2", "http/1.1"]),
            new EcPointFormatsExtension([0]),
            new SignatureAlgorithmsExtension([0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]),
            new ServerNameExtension(),
            new RenegotiationInfoExtension(),
            new CompressCertificateExtension([2]),
            new ExtendedMasterSecretExtension(),
            new ApplicationSettingsExtension(["h2"], Codepoint: 17613),
            new SupportedGroupsExtension([0x11EC, 29, 23, 24]),
            new EncryptedClientHelloGreaseExtension(),
            new SignedCertificateTimestampExtension(),
            new KeyShareExtension([0x11EC, 29]),
            new StatusRequestExtension(),
            new GreaseExtension(new byte[] { 0 }),
        ],
        Shuffle: ExtensionShufflePolicy.Chrome,
        Grease: GreasePlacement.CipherSuites | GreasePlacement.SupportedGroups | GreasePlacement.KeyShare
            | GreasePlacement.SupportedVersions | GreasePlacement.SignatureAlgorithms);

    private static Http2Profile ChromiumFamilyHttp2() => new(
        Preface:
        [
            new Http2SettingsFrame([new Http2Setting(1, 65536), new Http2Setting(2, 0), new Http2Setting(4, 6291456), new Http2Setting(6, 262144)]),
            new Http2WindowUpdateFrame(15663105),
        ],
        PseudoHeaderOrder: [PseudoHeader.Method, PseudoHeader.Authority, PseudoHeader.Scheme, PseudoHeader.Path],
        // Weight 220 (wire 219) for fetch(), 256 (wire 255) for navigations; always exclusive on stream 0.
        HeadersPriority: new Http2HeadersPriority(0, 219, true),
        HeadersPriorityOverrides: new Dictionary<RequestKind, Http2HeadersPriority>
        {
            [RequestKind.Navigate] = new(0, 255, true),
        });

    private static HeaderProfile ChromiumFamilyHeaders(string userAgent, string brands, bool navigationClientHints) => new(
        HeaderOrder:
        [
            "Host", "Connection", "Content-Length", "Pragma", "Cache-Control", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "Content-Type",
            "sec-ch-ua-mobile", "Accept", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding",
            "Accept-Language", "Cookie", "Priority",
        ],
        Overrides: new Dictionary<RequestKind, IReadOnlyList<string>>
        {
            [RequestKind.Navigate] =
            [
                "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent", "Accept",
                "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Referer", "Accept-Encoding", "Accept-Language", "Cookie", "Priority",
            ],
        },
        Http1Casing: HeaderCasing.AsSpecified,
        DefaultHeaders: new Dictionary<string, string>
        {
            ["Connection"] = "keep-alive",
            ["sec-ch-ua-platform"] = "\"Windows\"",
            ["User-Agent"] = userAgent,
            ["sec-ch-ua"] = brands,
            ["sec-ch-ua-mobile"] = "?0",
            ["Accept"] = "*/*",
            ["Sec-Fetch-Site"] = "same-origin",
            ["Sec-Fetch-Mode"] = "cors",
            ["Sec-Fetch-Dest"] = "empty",
            ["Accept-Encoding"] = "gzip, deflate, br, zstd",
            ["Accept-Language"] = "en-US,en;q=0.9",
            ["Priority"] = "u=1, i",
        },
        OrderMode: HeaderOrderMode.ProfileOrder,
        DefaultHeaderOverrides: new Dictionary<RequestKind, IReadOnlyDictionary<string, string>>
        {
            // Edge 153 sends the three client hints on navigations; the embedded Chromium 152 that was captured sent none.
            [RequestKind.Navigate] = new Dictionary<string, string>(navigationClientHints
                ? [new("sec-ch-ua", brands), new("sec-ch-ua-mobile", "?0"), new("sec-ch-ua-platform", "\"Windows\"")]
                : [])
            {
                ["Connection"] = "keep-alive",
                ["Upgrade-Insecure-Requests"] = "1",
                ["User-Agent"] = userAgent,
                ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                ["Sec-Fetch-Site"] = "none",
                ["Sec-Fetch-Mode"] = "navigate",
                ["Sec-Fetch-User"] = "?1",
                ["Sec-Fetch-Dest"] = "document",
                ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                ["Accept-Language"] = "en-US,en;q=0.9",
                ["Priority"] = "u=0, i",
            },
            [RequestKind.WebSocket] = new Dictionary<string, string>
            {
                ["Pragma"] = "no-cache",
                ["Cache-Control"] = "no-cache",
                ["User-Agent"] = userAgent,
                ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                ["Accept-Language"] = "en-US,en;q=0.9",
            },
        },
        Http2OnlyHeaders: ["Priority"]);

    private static WebSocketProfile ChromiumFamilyWebSocket() => new(
        HandshakeHeaderOrder:
        [
            "Host", "Connection", "Pragma", "Cache-Control", "User-Agent", "Upgrade", "Origin", "Sec-WebSocket-Version", "Accept-Encoding",
            "Accept-Language", "Cookie", "Sec-WebSocket-Key", "Sec-WebSocket-Extensions",
        ],
        PerMessageDeflateOffer: "permessage-deflate; client_max_window_bits",
        Alpn: ["http/1.1"]);
}
