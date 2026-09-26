using System.Collections.ObjectModel;

namespace Chameleon.Net.Profiles;

public static partial class BuiltInProfiles
{
    /// <summary>OkHttp 4.x on Android 13 (Conscrypt/BoringSSL). Expected JA3:
    /// 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0</summary>
    public static ClientProfile OkHttp4Android13 { get; } = new(
        Identity: new ProfileIdentity("okhttp4_android_13", ClientPlatform.Android, "OkHttp", "4"),
        Tls: new TlsProfile(
            CipherSuites: [4865, 4866, 4867, 49195, 49199, 49196, 49200, 52393, 52392, 49171, 49172, 156, 157, 47, 53],
            Extensions:
            [
                new ServerNameExtension(),
                new ExtendedMasterSecretExtension(),
                new RenegotiationInfoExtension(),
                new SupportedGroupsExtension([29, 23, 24]),
                new EcPointFormatsExtension([0]),
                new SessionTicketExtension(),
                new AlpnExtension(["h2", "http/1.1"]),
                new StatusRequestExtension(),
                new SignatureAlgorithmsExtension([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201]),
                new KeyShareExtension([29]),
                new PskKeyExchangeModesExtension([1]),
                new SupportedVersionsExtension([0x0304, 0x0303]),
                new PaddingExtension(TargetClientHelloLength: 512),
            ],
            Shuffle: ExtensionShufflePolicy.None,
            Grease: GreasePlacement.None),
        Http2: new Http2Profile(
            Preface:
            [
                // Http2Connection.okHttpSettings sets INITIAL_WINDOW_SIZE only; start() then tops the connection window up to the same 16 MiB.
                new Http2SettingsFrame([new Http2Setting(4, 16777216)]),
                new Http2WindowUpdateFrame(16711681),
            ],
            PseudoHeaderOrder: [PseudoHeader.Method, PseudoHeader.Path, PseudoHeader.Authority, PseudoHeader.Scheme],
            HeadersPriority: null),
        Headers: new HeaderProfile(
            HeaderOrder: ["Content-Type", "Content-Length", "Transfer-Encoding", "Host", "Connection", "Accept-Encoding", "Cookie", "User-Agent"],
            Overrides: ReadOnlyDictionary<RequestKind, IReadOnlyList<string>>.Empty,
            Http1Casing: HeaderCasing.AsSpecified,
            DefaultHeaders: new Dictionary<string, string>
            {
                ["Connection"] = "Keep-Alive",
                ["Accept-Encoding"] = "gzip",
                ["User-Agent"] = "okhttp/4.12.0",
            },
            OrderMode: HeaderOrderMode.CallerFirst),
        WebSocket: new WebSocketProfile(
            HandshakeHeaderOrder: ["Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Host", "Accept-Encoding", "Cookie", "User-Agent"],
            PerMessageDeflateOffer: "permessage-deflate",
            Alpn: ["http/1.1"]));
}
