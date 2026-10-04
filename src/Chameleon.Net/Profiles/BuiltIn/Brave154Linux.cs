namespace Chameleon.Net.Profiles;

public static partial class BuiltInProfiles
{
    /// <summary>Brave 154.1.96.61 on GitHub Actions ubuntu24 (image 20260927.320.1).
    /// <para>Captured 2026-10-03 by the Chameleon.Net Inspector's automated capture (eng/profile-capture), then reviewed.</para>
    /// <para>Expected JA4 <c>t13d1516h2_8daaf6152771_806a8c22fdea</c> (JA3 changes per connection: extension shuffle); Akamai <c>1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p</c>.</para>
    /// <para>From the capture:</para>
    /// <list type="bullet">
    /// <item>Seen: 4 TLS connection(s); Navigate over HTTP/2 (1), Fetch over HTTP/2 (2), WebSocket over HTTP/1.1 (3), Navigate over HTTP/1.1 (1), Fetch over HTTP/1.1 (1).</item>
    /// </list>
    /// </summary>
    public static ClientProfile Brave154Linux { get; } = new(
        Identity: new ProfileIdentity("brave_154_linux", ClientPlatform.Linux, "Brave", "154"),
        Tls: new TlsProfile(
            CipherSuites: [4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
            Extensions:
            [
                new GreaseExtension(),
                new SupportedGroupsExtension([0x11EC, 29, 23, 24]),
                new SignedCertificateTimestampExtension(),
                new EncryptedClientHelloGreaseExtension(),
                new SupportedVersionsExtension([0x0304, 0x0303]),
                new PskKeyExchangeModesExtension([1]),
                new EcPointFormatsExtension([0]),
                new CompressCertificateExtension([2]),
                new ApplicationSettingsExtension(["h2"], Codepoint: 17613),
                new ServerNameExtension(),
                new AlpnExtension(["h2", "http/1.1"]),
                new ExtendedMasterSecretExtension(),
                new StatusRequestExtension(),
                new RenegotiationInfoExtension(),
                new SessionTicketExtension(),
                new SignatureAlgorithmsExtension([0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]),
                new KeyShareExtension([0x11EC, 29]),
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
            Hpack: new HpackProfile(SplitCookies: true),
            FlowControl: new Http2FlowControl(ConnectionWindowUpdate.HalfOfConnectionWindow)),
        Headers: new HeaderProfile(
            HeaderOrder:
            [
                "Host", "Connection", "Content-Length", "sec-ch-ua-platform", "User-Agent", "sec-ch-ua", "Content-Type",
                "sec-ch-ua-mobile", "Accept", "Sec-GPC", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Referer",
                "Accept-Encoding", "Accept-Language", "Cookie", "Priority",
            ],
            Overrides: new Dictionary<RequestKind, IReadOnlyList<string>>
            {
                [RequestKind.Navigate] =
                [
                    "Host", "Connection", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "Upgrade-Insecure-Requests", "User-Agent",
                    "Accept", "Sec-GPC", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding",
                    "Accept-Language", "Cookie", "Priority",
                ],
            },
            Http1Casing: HeaderCasing.AsSpecified,
            DefaultHeaders: new Dictionary<string, string>
            {
                ["sec-ch-ua-platform"] = "\"Linux\"",
                ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
                ["sec-ch-ua"] = "\"Chromium\";v=\"154\", \"Brave\";v=\"154\", \"Not A(Brand\";v=\"99\"",
                ["sec-ch-ua-mobile"] = "?0",
                ["Accept"] = "*/*",
                ["Sec-GPC"] = "1",
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
                    ["sec-ch-ua"] = "\"Chromium\";v=\"154\", \"Brave\";v=\"154\", \"Not A(Brand\";v=\"99\"",
                    ["sec-ch-ua-mobile"] = "?0",
                    ["sec-ch-ua-platform"] = "\"Linux\"",
                    ["Upgrade-Insecure-Requests"] = "1",
                    ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
                    ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
                    ["Sec-GPC"] = "1",
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
                    ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
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
