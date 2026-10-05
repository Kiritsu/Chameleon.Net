namespace Chameleon.Net.Profiles;

public static partial class BuiltInProfiles
{
    /// <summary>Opera 136.0.6008.80 on GitHub Actions ubuntu24 (image 20260927.320.1).
    /// <para>Captured 2026-10-05 by the Chameleon.Net Inspector's automated capture (eng/profile-capture), then reviewed.</para>
    /// <para>Expected JA4 <c>t13d1517h2_8daaf6152771_cb7bf5808d99</c> (JA3 changes per connection: extension shuffle); Akamai <c>1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p</c>.</para>
    /// <para>From the capture:</para>
    /// <list type="bullet">
    /// <item>Seen: 4 TLS connection(s); Navigate over HTTP/2 (1), Fetch over HTTP/2 (2), WebSocket over HTTP/1.1 (3), Navigate over HTTP/1.1 (1), Fetch over HTTP/1.1 (1).</item>
    /// <item>Extension 51764 (unknown) is copied as raw bytes: Chameleon.Net sends it but doesn't act on it.</item>
    /// </list>
    /// </summary>
    public static ClientProfile Opera136Linux { get; } = new(
        Identity: new ProfileIdentity("opera_136_linux", ClientPlatform.Linux, "Opera", "136"),
        Tls: new TlsProfile(
            CipherSuites: [4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
            Extensions:
            [
                new GreaseExtension(),
                new RenegotiationInfoExtension(),
                new EncryptedClientHelloGreaseExtension(),
                new AlpnExtension(["h2", "http/1.1"]),
                new SessionTicketExtension(),
                new ApplicationSettingsExtension(["h2"], Codepoint: 17613),
                new SupportedVersionsExtension([0x0304, 0x0303]),
                new EcPointFormatsExtension([0]),
                new ServerNameExtension(),
                new PskKeyExchangeModesExtension([1]),
                new SupportedGroupsExtension([0x11EC, 29, 23, 24]),
                new StatusRequestExtension(),
                new KeyShareExtension([0x11EC, 29]),
                new SignedCertificateTimestampExtension(),
                new ExtendedMasterSecretExtension(),
                new SignatureAlgorithmsExtension([0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]),
                new CompressCertificateExtension([2]),
                new RawExtension(51764, new byte[] { 0, 204, 4, 214, 121, 9, 6, 4, 214, 121, 9, 9, 4, 214, 121, 9, 15, 8, 131, 154, 100, 140, 155, 45, 1, 13, 5, 130, 223, 19, 2, 1, 4, 214, 121, 9, 4, 4, 214, 121, 9, 10, 5, 130, 223, 19, 2, 20, 8, 131, 154, 100, 140, 155, 45, 1, 7, 4, 214, 121, 9, 7, 8, 131, 154, 100, 140, 155, 45, 1, 12, 4, 214, 121, 9, 5, 8, 131, 154, 100, 140, 155, 45, 1, 19, 4, 214, 121, 9, 11, 4, 214, 121, 9, 12, 8, 131, 154, 100, 140, 155, 45, 1, 18, 4, 214, 121, 9, 3, 5, 130, 223, 19, 2, 13, 8, 131, 154, 100, 140, 155, 45, 1, 11, 8, 131, 154, 100, 140, 155, 45, 1, 10, 4, 214, 121, 9, 1, 5, 130, 223, 19, 2, 14, 4, 214, 121, 9, 13, 5, 130, 223, 19, 2, 15, 5, 130, 223, 19, 2, 18, 8, 131, 154, 100, 140, 155, 45, 1, 9, 4, 214, 121, 9, 8, 4, 214, 121, 9, 2, 4, 214, 121, 9, 14, 5, 130, 223, 19, 2, 6, 5, 130, 223, 19, 2, 19, 8, 131, 154, 100, 140, 155, 45, 1, 8 }),
                new GreaseExtension(new byte[] { 0 }),
            ],
            Shuffle: ExtensionShufflePolicy.Chrome,
            Grease: GreasePlacement.CipherSuites | GreasePlacement.SupportedGroups | GreasePlacement.KeyShare | GreasePlacement.SupportedVersions | GreasePlacement.SignatureAlgorithms),
        Http2: new Http2Profile(
            Preface:
            [
                new Http2SettingsFrame([new Http2Setting(1, 65536), new Http2Setting(2, 0), new Http2Setting(4, 6291456), new Http2Setting(6, 262144)]),
                new Http2WindowUpdateFrame(15663105),
            ],
            PseudoHeaderOrder: [PseudoHeader.Method, PseudoHeader.Authority, PseudoHeader.Scheme, PseudoHeader.Path],
            HeadersPriority: new Http2HeadersPriority(0, 219, true),
            HeadersPriorityOverrides: new Dictionary<RequestKind, Http2HeadersPriority>
            {
                [RequestKind.Navigate] = new Http2HeadersPriority(0, 255, true),
            },
            FirstStreamId: 1,
            Hpack: new HpackProfile(SplitCookies: true)),
        Headers: new HeaderProfile(
            HeaderOrder:
            [
                "Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "Content-Type",
                "sec-ch-ua-mobile", "Accept", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer", "Accept-Encoding",
                "Accept-Language", "Cookie", "Priority",
            ],
            Overrides: new Dictionary<RequestKind, IReadOnlyList<string>>
            {
                [RequestKind.Navigate] =
                [
                    "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent",
                    "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language",
                    "Cookie", "Priority",
                ],
            },
            Http1Casing: HeaderCasing.AsSpecified,
            DefaultHeaders: new Dictionary<string, string>
            {
                ["sec-ch-ua-platform"] = "\"Linux\"",
                ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 OPR/136.0.0.0",
                ["sec-ch-ua"] = "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Opera\";v=\"136\"",
                ["sec-ch-ua-mobile"] = "?0",
                ["Accept"] = "*/*",
                ["Sec-Fetch-Site"] = "same-origin",
                ["Sec-Fetch-Mode"] = "cors",
                ["Sec-Fetch-Dest"] = "empty",
                ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                ["Accept-Language"] = "en-US,en;q=0.9",
                ["Priority"] = "u=1, i",
                ["Connection"] = "keep-alive",
            },
            OrderMode: HeaderOrderMode.ProfileOrder,
            DefaultHeaderOverrides: new Dictionary<RequestKind, IReadOnlyDictionary<string, string>>
            {
                [RequestKind.Navigate] = new Dictionary<string, string>
                {
                    ["sec-ch-ua"] = "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Opera\";v=\"136\"",
                    ["sec-ch-ua-mobile"] = "?0",
                    ["sec-ch-ua-platform"] = "\"Linux\"",
                    ["Upgrade-Insecure-Requests"] = "1",
                    ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 OPR/136.0.0.0",
                    ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    ["Sec-Fetch-Site"] = "none",
                    ["Sec-Fetch-Mode"] = "navigate",
                    ["Sec-Fetch-User"] = "?1",
                    ["Sec-Fetch-Dest"] = "document",
                    ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                    ["Accept-Language"] = "en-US,en;q=0.9",
                    ["Priority"] = "u=0, i",
                    ["Connection"] = "keep-alive",
                },
                [RequestKind.WebSocket] = new Dictionary<string, string>
                {
                    ["Pragma"] = "no-cache",
                    ["Cache-Control"] = "no-cache",
                    ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36 OPR/136.0.0.0",
                    ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                    ["Accept-Language"] = "en-US,en;q=0.9",
                },
            },
            Http2OnlyHeaders: ["Priority"]),
        WebSocket: new WebSocketProfile(
            HandshakeHeaderOrder:
            [
                "Host", "Connection", "Pragma", "Cache-Control", "User-Agent", "Upgrade", "Origin", "Sec-WebSocket-Version",
                "Accept-Encoding", "Accept-Language", "Cookie", "Sec-WebSocket-Key", "Sec-WebSocket-Extensions",
            ],
            PerMessageDeflateOffer: "permessage-deflate; client_max_window_bits",
            Alpn: ["http/1.1"]));
}
