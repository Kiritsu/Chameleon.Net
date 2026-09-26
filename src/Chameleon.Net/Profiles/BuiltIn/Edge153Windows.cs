namespace Chameleon.Net.Profiles;

public static partial class BuiltInProfiles
{
    /// <summary>Microsoft Edge 153 on Windows: Chromium's network stack with Edge's brand strings.
    /// <para>Captured 2026-09-26 from Edge 153.0.4234.48 (headless, fresh profile, driven over CDP): TLS and HTTP/2 via tls.peet.ws on
    /// three launches, HTTP/1.1, fetch()/POST, cookies and the WebSocket handshake via a local capture server. Every layer below the
    /// brand strings is identical to <see cref="Chromium152Windows"/>: JA4 <c>t13d1516h2_8daaf6152771_806a8c22fdea</c> (resumed:
    /// <c>t13d1517h2_8daaf6152771_a87ad97598a9</c>), Akamai <c>1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p</c>, same header order.</para>
    /// <para>Adjusted: headless mode reports <c>HeadlessChrome/153</c> in the User-Agent, replaced with the headed <c>Chrome/153</c>;
    /// Accept-Language made generic. Unlike the embedded Chromium capture, Edge sends its client hints on navigations.</para>
    /// <para>Differences from the real client: bodies a server sends zstd-encoded are returned undecoded, with Content-Encoding kept.</para></summary>
    public static ClientProfile Edge153Windows { get; } = new(
        Identity: new ProfileIdentity("edge_153_windows", ClientPlatform.Windows, "Edge", "153"),
        Tls: ChromiumFamilyTls(),
        Http2: ChromiumFamilyHttp2(),
        Headers: ChromiumFamilyHeaders(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36 Edg/153.0.0.0",
            "\"Microsoft Edge\";v=\"153\", \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"153\"",
            navigationClientHints: true),
        WebSocket: ChromiumFamilyWebSocket());
}
