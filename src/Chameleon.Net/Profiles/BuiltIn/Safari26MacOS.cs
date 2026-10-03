namespace Chameleon.Net.Profiles;

public static partial class BuiltInProfiles
{
    /// <summary>Safari 26.6.2 on GitHub Actions macos26 (image 20260907.0351.1).
    /// <para>Captured 2026-10-03 by the Chameleon.Net Inspector's automated capture (eng/profile-capture), then reviewed.</para>
    /// <para>Expected JA4 <c>t13d2013h2_a09f3c656075_7f0f34a4126d</c>, JA3 <c>ecdf4f49dd59effc439639da29186671</c>; Akamai <c>2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p</c>.</para>
    /// <para>From the capture:</para>
    /// <list type="bullet">
    /// <item>Seen: 4 TLS connection(s); Navigate over HTTP/2 (1), Fetch over HTTP/2 (2), WebSocket over HTTP/1.1 (3), Navigate over HTTP/1.1 (1), Fetch over HTTP/1.1 (1).</item>
    /// </list>
    /// </summary>
    public static ClientProfile Safari26MacOS { get; } = new(
        Identity: new ProfileIdentity("safari_26_macos", ClientPlatform.MacOS, "Safari", "26"),
        Tls: new TlsProfile(
            CipherSuites:
            [
                4866, 4867, 4865, 49196, 49195, 52393, 49200, 49199, 52392, 49162, 49161, 49172, 49171, 157, 156, 53, 47, 49160, 49170, 10,
            ],
            Extensions:
            [
                new GreaseExtension(),
                new ServerNameExtension(),
                new ExtendedMasterSecretExtension(),
                new RenegotiationInfoExtension(),
                new SupportedGroupsExtension([0x11EC, 29, 23, 24, 25]),
                new EcPointFormatsExtension([0]),
                new AlpnExtension(["h2", "http/1.1"]),
                new StatusRequestExtension(),
                new SignatureAlgorithmsExtension([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]),
                new SignedCertificateTimestampExtension(),
                new KeyShareExtension([0x11EC, 29]),
                new PskKeyExchangeModesExtension([1]),
                new SupportedVersionsExtension([0x0304, 0x0303]),
                new CompressCertificateExtension([1]),
                new GreaseExtension(new byte[] { 0 }),
            ],
            Shuffle: ExtensionShufflePolicy.None,
            Grease: GreasePlacement.CipherSuites | GreasePlacement.SupportedGroups | GreasePlacement.KeyShare | GreasePlacement.SupportedVersions),
        Http2: new Http2Profile(
            Preface:
            [
                new Http2SettingsFrame([new Http2Setting(2, 0), new Http2Setting(3, 100), new Http2Setting(4, 2097152), new Http2Setting(9, 1)]),
                new Http2WindowUpdateFrame(10420225),
            ],
            PseudoHeaderOrder: [PseudoHeader.Method, PseudoHeader.Scheme, PseudoHeader.Authority, PseudoHeader.Path],
            HeadersPriority: null,
            FirstStreamId: 1),
        Headers: new HeaderProfile(
            HeaderOrder:
            [
                "Host", "Sec-Fetch-Dest", "User-Agent", "Accept", "Content-Type", "Origin", "Referer", "Sec-Fetch-Site", "Sec-Fetch-Mode",
                "Content-Length", "Accept-Language", "Priority", "Accept-Encoding", "Cookie", "Connection",
            ],
            Overrides: new Dictionary<RequestKind, IReadOnlyList<string>>
            {
                [RequestKind.Navigate] =
                [
                    "Host", "Sec-Fetch-Dest", "User-Agent", "Upgrade-Insecure-Requests", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode",
                    "Accept-Language", "Priority", "Accept-Encoding", "Cookie", "Connection",
                ],
            },
            Http1Casing: HeaderCasing.AsSpecified,
            DefaultHeaders: new Dictionary<string, string>
            {
                ["Sec-Fetch-Dest"] = "empty",
                ["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15",
                ["Accept"] = "*/*",
                ["Sec-Fetch-Site"] = "same-origin",
                ["Sec-Fetch-Mode"] = "cors",
                ["Accept-Language"] = "en-US,en;q=0.9",
                ["Priority"] = "u=3, i",
                ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                ["Connection"] = "keep-alive",
            },
            OrderMode: HeaderOrderMode.ProfileOrder,
            DefaultHeaderOverrides: new Dictionary<RequestKind, IReadOnlyDictionary<string, string>>
            {
                [RequestKind.Navigate] = new Dictionary<string, string>
                {
                    ["Sec-Fetch-Dest"] = "document",
                    ["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15",
                    ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    ["Sec-Fetch-Site"] = "none",
                    ["Sec-Fetch-Mode"] = "navigate",
                    ["Accept-Language"] = "en-US,en;q=0.9",
                    ["Priority"] = "u=0, i",
                    ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                    ["Upgrade-Insecure-Requests"] = "1",
                    ["Connection"] = "keep-alive",
                },
                [RequestKind.WebSocket] = new Dictionary<string, string>
                {
                    ["Pragma"] = "no-cache",
                    ["Sec-Fetch-Site"] = "same-origin",
                    ["Sec-Fetch-Mode"] = "websocket",
                    ["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15",
                    ["Cache-Control"] = "no-cache",
                    ["Sec-Fetch-Dest"] = "websocket",
                    ["Accept"] = "*/*",
                    ["Accept-Language"] = "en-US,en;q=0.9",
                    ["Priority"] = "u=3, i",
                    ["Accept-Encoding"] = "gzip, deflate, br, zstd",
                },
            },
            Http2OnlyHeaders: null),
        WebSocket: new WebSocketProfile(
            HandshakeHeaderOrder:
            [
                "Host", "Origin", "Pragma", "Sec-Fetch-Site", "Sec-WebSocket-Version", "Sec-Fetch-Mode", "User-Agent",
                "Sec-WebSocket-Extensions", "Cache-Control", "Sec-Fetch-Dest", "Accept", "Accept-Language", "Priority", "Accept-Encoding",
                "Cookie", "Sec-WebSocket-Key", "Connection", "Upgrade",
            ],
            PerMessageDeflateOffer: "permessage-deflate",
            Alpn: ["http/1.1"]));
}
