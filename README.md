# Chameleon.Net

An `HttpMessageHandler` and a WebSocket connector for .NET whose connections look like a specific real client
on the wire: the TLS ClientHello, the HTTP/2 connection preface and frames, and the order, casing and defaults of
the HTTP headers. Each client is described by a **profile**; the built-in ones were captured from the real clients and
are checked against them by tests.

TLS is done by [BouncyCastle](https://www.bouncycastle.org/) instead of SChannel/OpenSSL, because the OS stacks don't
let you choose the ClientHello. HTTP/1.1, HTTP/2 (with HPACK) and the WebSocket handshake are implemented here for
the same reason; the WebSocket framing itself is .NET's own `WebSocket`.

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
would (gzip, deflate, br).

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
- zstd: response bodies sent with `Content-Encoding: zstd` are returned undecoded, and zstd certificate compression
  (offered by the Firefox profile) isn't supported; there is no zstd decoder in .NET 10.
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
