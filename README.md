# Chameleon.Net

An `HttpMessageHandler` and a WebSocket connector for .NET whose connections look like a specific real client
on the wire: the TLS ClientHello, the HTTP/2 connection preface and frames, and the order, casing and defaults of
the HTTP headers. Each client is described by a **profile**; the built-in ones were captured from the real clients and
are checked against them by tests.

## Why this exists

Servers and the CDNs in front of them (Cloudflare, Akamai, ...) don't only look at the `User-Agent`. They also
fingerprint *how* a client talks:

- **TLS**: the ClientHello lists cipher suites, extensions, groups and signature algorithms in an order that is
  specific to each TLS library and version. [JA3](https://github.com/salesforce/ja3) and
  [JA4](https://github.com/FoxIO-LLC/ja4) turn it into a short hash.
- **HTTP/2**: the SETTINGS, WINDOW_UPDATE and PRIORITY frames a client opens with, and the order of its pseudo-headers,
  differ between Chrome, Firefox, OkHttp, curl... (the "Akamai fingerprint").
- **HTTP headers**: which headers are sent, in which order, with which casing and default values.

A .NET `HttpClient` has its own fingerprint on each of these: SChannel on Windows, OpenSSL on Linux, and .NET's HTTP
stack. It matches none of the clients an app usually claims to be. If a service expects its Android app (OkHttp)
or a browser, a .NET client saying so in its `User-Agent` stands out at the first packet, and bot protection
blocks it or serves it a challenge. This happens even when the traffic is legitimate: testing your own backend through
its real edge, a desktop or server companion to a mobile app, research on fingerprinting itself.

.NET gives no way to change any of this: `SslStream` doesn't let you choose the ClientHello, and `SocketsHttpHandler`
decides its HTTP/2 frames and header order itself. Chameleon.Net replaces those layers so that a connection
reproduces a real client's fingerprint on every one of them.

## How it works

A request goes through four layers. Each one is driven by the profile:

1. **Transport**: a TCP connection, possibly through an HTTP (CONNECT) or SOCKS5 proxy. The proxy doesn't change what
   the target sees.
2. **TLS**, by [BouncyCastle](https://www.bouncycastle.org/) rather than the OS:
   - The profile supplies the content (cipher suites, groups, signature algorithms, ALPN...). BouncyCastle runs the
     handshake and owns the key schedule.
   - The ClientHello bytes are written by Chameleon.Net itself: extensions in the profile's order, GREASE values,
     Chrome's per-connection extension shuffle, and padding. The handshake transcript is fed those exact bytes, so
     what goes on the wire is what gets authenticated.
   - Chameleon.Net also fills in what browsers need and BouncyCastle lacks: X25519MLKEM768 post-quantum key shares,
     compressed certificates (brotli/zlib/zstd), ALPS, GREASE ECH, and TLS 1.3 session resumption with tickets
     reused like BoringSSL does.
3. **HTTP**: HTTP/1.1 and HTTP/2 (with HPACK) are implemented here, not taken from .NET, so the profile controls the
   HTTP/2 preface, stream priorities, pseudo-header order, first stream id, header order, casing and defaults per
   request kind. Connection pooling, redirects, cookies and decompression follow the emulated client (OkHttp's
   pool semantics for the OkHttp profile).
4. **WebSocket**: the upgrade request is written in the profile's header order over the same TLS layer (ALPN
   `http/1.1`). The connection is then handed to .NET's own `WebSocket` for framing.

A **profile** (`ClientProfile`) is plain data: a `TlsProfile`, an `Http2Profile`, a `HeaderProfile` and a
`WebSocketProfile`. The built-in ones were captured from the real clients. Their tests replay those captures offline
(JA3/JA4, HTTP/2 frames, header lists), and explicit live tests check that an echo service such as tls.peet.ws sees
the same fingerprints from Chameleon.Net as from the real client.

## Built-in profiles

| Profile | Client | JA4 | Akamai HTTP/2 |
|---|---|---|---|
| `OkHttp4Android13` | OkHttp 4.12 on Android 13 (Conscrypt) | `t13d1513h2_…` | `4:16777216\|16711681\|0\|m,p,a,s` |
| `Chromium152Windows` | Chromium 152 | `t13d1516h2_8daaf6152771_806a8c22fdea` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `Edge153Windows` | Microsoft Edge 153 | `t13d1516h2_8daaf6152771_806a8c22fdea` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `Firefox156Windows` | Firefox 156 | `t13d1517h2_8daaf6152771_3cbfd9057e0d` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` |

What the profiles reproduce, depending on the client: cipher suite and extension order, GREASE (placement and
per-connection values), Chrome's extension shuffle, X25519MLKEM768 post-quantum key shares, certificate compression,
ALPS, GREASE ECH, record size limit, TLS 1.3 session resumption, HTTP/2 SETTINGS / WINDOW_UPDATE / HEADERS priority /
pseudo-header order / first stream id, header order and defaults per request kind (navigation, `fetch()`, WebSocket),
and OkHttp's connection pooling and header handling.

## Usage

Requires .NET 10.

```csharp
using Chameleon.Net;
using Chameleon.Net.Http;
using Chameleon.Net.Profiles;

using var client = new HttpClient(new ChameleonHttpMessageHandler(BuiltInProfiles.OkHttp4Android13));
var body = await client.GetStringAsync("https://example.com/");
```

Headers you set on the request are kept; what the profile's client would add on its own (`User-Agent`,
`Accept-Encoding`, ...) is added when missing, in the client's order. Responses are decompressed like the client
would (gzip, deflate, br, zstd).

Browser profiles distinguish request kinds, because browsers send different headers and HTTP/2 priorities for each:

```csharp
using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com/");
request.Options.Set(ChameleonRequestOptions.Kind, RequestKind.Navigate); // default: Fetch
```

### WebSockets

```csharp
using Chameleon.Net.WebSockets;

var connector = new ChameleonWebSocketConnector();
using var socket = await connector.ConnectAsync(new Uri("wss://example.com/ws"), BuiltInProfiles.OkHttp4Android13);
```

`ChameleonWebSocketOptions` adds headers, sub-protocols and a keep-alive interval. A non-101 answer throws
`WebSocketUpgradeRejectedException` with the status code.

### Options

```csharp
using System.Net;
using Chameleon.Net.Tls;

var options = new ChameleonOptions
{
    ProfileSelector = new RoundRobinProfileSelector([BuiltInProfiles.Chromium152Windows, BuiltInProfiles.Edge153Windows]),
    Proxy = new WebProxy("socks5://user:pass@proxy.example:1080"),
    Cookies = new CookieContainer(),
    TlsSessionCache = new TlsSessionCache(),
    LoggerFactory = loggerFactory,
};

using var client = new HttpClient(new ChameleonHttpMessageHandler(options));
var connector = new ChameleonWebSocketConnector(options);
```

- **`ProfileSelector`**: `FixedProfileSelector`, `RoundRobinProfileSelector`, `RandomProfileSelector` (optionally
  weighted with `WeightedProfile`). Chosen per new connection.
- **`Proxy`**: `http://` proxies (CONNECT for https and wss, absolute-form requests for plain http, like OkHttp) and
  `socks5://` proxies, with credentials from the URI or `IWebProxy.Credentials`.
- **`Cookies`**: a `CookieContainer`, sent at the profile's position and filled from `Set-Cookie`.
- **`TlsSessionResumption`** (on by default) and **`TlsSessionCache`**: give the handler and the WebSocket connector
  the same cache and the WebSocket connection resumes the TLS session of earlier requests, as one OkHttpClient does.
- **`CertificateValidator`**: defaults to the OS trust store.
- **`ConnectTimeout`**, **`AllowAutoRedirect`**, **`MaxAutomaticRedirections`**, **`LoggerFactory`**.

### Checking a fingerprint

`TlsFingerprinter.Compute(ClientHelloParser.Parse(bytes))` gives JA3, JA4 and JA4_r for a captured ClientHello
record; `AkamaiFingerprint.Compute(profile.Http2)` gives the Akamai HTTP/2 string. Services such as
<https://tls.peet.ws/api/all> show what a server sees.

## Creating a profile

[docs/creating-a-profile.md](docs/creating-a-profile.md) covers capturing a client (packet capture, tls.peet.ws, or a
scripted headless browser), turning the capture into a profile, and verifying it.

## Limitations

- HTTP/3 and QUIC are not implemented; neither is real ECH (GREASE ECH is).
- Delegated credentials (offered by the Firefox profile) are not supported if a server uses them.
- WebSockets always go over HTTP/1.1 (no RFC 8441).
- TCP/IP-level fingerprints (TTL, window size, options) come from the OS.

## Building and testing

```bash
dotnet build Chameleon.Net.slnx
dotnet test --solution Chameleon.Net.slnx
```

The default test run is offline. Tests that talk to real servers (tls.peet.ws, Cloudflare, Google, ...) are marked
explicit and run with:

```bash
dotnet test --solution Chameleon.Net.slnx -- --explicit only
```

CI runs the offline tests on Linux and Windows for every push and pull request; the live tests can be started by hand
from the Actions tab.
