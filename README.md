# Chameleon.Net

[![NuGet](https://img.shields.io/nuget/v/Chameleon.Net.svg?label=Chameleon.Net)](https://www.nuget.org/packages/Chameleon.Net)
[![NuGet](https://img.shields.io/nuget/v/Chameleon.Net.Extensions.Http.svg?label=Chameleon.Net.Extensions.Http)](https://www.nuget.org/packages/Chameleon.Net.Extensions.Http)

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
   - BouncyCastle runs in its non-blocking mode: Chameleon.Net reads and writes the socket with async I/O and hands
     the bytes to it. A connection waiting for data, such as an idle WebSocket, holds no thread.
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

| Latest | Profile | Client | JA4 | Akamai HTTP/2 |
|---|---|---|---|---|
| | `OkHttp4Android13` | OkHttp 4.12 on Android 13 (Conscrypt) | `t13d1513h2_…` | `4:16777216\|16711681\|0\|m,p,a,s` |
| | `Chromium152Windows` | Chromium 152 | `t13d1516h2_8daaf6152771_806a8c22fdea` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `EdgeWindows` | `Edge153Windows` | Microsoft Edge 153 | `t13d1516h2_8daaf6152771_806a8c22fdea` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| `FirefoxWindows` | `Firefox156Windows` | Firefox 156 | `t13d1517h2_8daaf6152771_3cbfd9057e0d` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` |

These are the hand-made profiles. Newer versions of each browser, on Windows, macOS and Linux, arrive through the
automated capture below, so `src/Chameleon.Net/Profiles/BuiltIn/` has the full list. A "latest" alias, such as
`BuiltInProfiles.EdgeWindows` or `ChromeMacOS`, always points to the newest profile of that browser on that OS. A
versioned name like `Edge153Windows` stays the same forever.

What the profiles reproduce, depending on the client: cipher suite and extension order, GREASE (placement and
per-connection values), Chrome's extension shuffle, X25519MLKEM768 post-quantum key shares, certificate compression,
ALPS, GREASE ECH, record size limit, TLS 1.3 session resumption, HTTP/2 SETTINGS / WINDOW_UPDATE / HEADERS priority /
pseudo-header order / first stream id, header order and defaults per request kind (navigation, `fetch()`, WebSocket),
and OkHttp's connection pooling and header handling.

## Installation

Requires .NET 10.

```bash
dotnet add package Chameleon.Net
```

For `IHttpClientFactory` and dependency injection:

```bash
dotnet add package Chameleon.Net.Extensions.Http
```

## Usage

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

### IHttpClientFactory and dependency injection

The `Chameleon.Net.Extensions.Http` package plugs the handler into `IHttpClientFactory`:

```csharp
services.AddHttpClient("api", client => client.BaseAddress = new Uri("https://api.example.com/"))
    .UseChameleon(BuiltInProfiles.OkHttp4Android13, options => options.Cookies = new CookieContainer());

services.AddHttpClient<GitHubClient>()
    .UseChameleon(BuiltInProfiles.Chromium152Windows);

// Profile selection or options taken from the container:
services.AddHttpClient("rotating")
    .UseChameleon((provider, options) => options.ProfileSelector = provider.GetRequiredService<IProfileSelector>());

services.AddChameleonWebSocketConnector(); // ChameleonWebSocketConnector and IWebSocketConnector, as singletons
```

- Logging goes to the container's `ILoggerFactory`.
- Every client and the WebSocket connector share one `TlsSessionCache`, so a WebSocket resumes the TLS session of earlier
  requests to the same host, like one OkHttpClient used for both. Tickets are still kept apart per profile and per
  certificate validator.
- `UseChameleon` sets the handler lifetime to infinite. The handler closes idle connections itself (OkHttp's pool
  rules), and IHttpClientFactory's default two-minute rotation would throw away its connections, TLS sessions and
  cookies, which the real clients keep. Call `SetHandlerLifetime` afterwards to change it.

### Checking a fingerprint

`TlsFingerprinter.Compute(ClientHelloParser.Parse(bytes))` gives JA3, JA4 and JA4_r for a captured ClientHello
record; `AkamaiFingerprint.Compute(profile.Http2)` gives the Akamai HTTP/2 string. Services such as
<https://tls.peet.ws/api/all> show what a server sees.

### Inspector

`tools/Chameleon.Net.Inspector` is a local server that shows what a CDN can see of any client (Chameleon.Net, a browser, an
app on a phone, curl...) and where it contradicts its `User-Agent`:

```bash
dotnet run --project tools/Chameleon.Net.Inspector -- --port 8443
```

- **TLS**: JA3, JA4, JA4_r and every ClientHello field: cipher suites, extensions in order, groups and key shares,
  GREASE positions, ALPS, certificate compression, ECH, PSK. It also tracks whether the extension order changes between
  connections.
- **HTTP/2**: the Akamai fingerprint read from the frames as they arrived, every frame before the first request,
  HEADERS priority, first stream id and pseudo-header order.
- **HTTP**: header names in order with their casing, and JA4H. WebSocket upgrades are included.
- **Consistency**: which known client the TLS and HTTP/2 fingerprints match (the built-in profiles), and checks of the kind
  bot management runs on every request:
  - the TLS stack or HTTP/2 preface belongs to another client than the `User-Agent` claims;
  - Chrome without its extension shuffle or post-quantum key share;
  - `sec-ch-ua` contradicting the `User-Agent`;
  - header order, casing or defaults that differ from the claimed client;
  - SNI not matching the host.
  
  Findings are graded and summed up in a verdict. It's a heuristic: Cloudflare's and Akamai's real scoring also uses
  traffic statistics and JavaScript challenges, and TCP/IP fingerprints need a packet capture.

TLS and plain HTTP share the port: HTTP/2 over TLS through ALPN, HTTP/1.1, and h2c with prior knowledge. Every request
gets its report as JSON; a WebSocket gets it as its first message. The console prints a summary, and `--log` appends each
report to a JSON-lines file. The certificate is self-signed, so clients have to skip validation. One that rejects it
still gets its ClientHello reported. `--listen any` lets a phone on the same network connect.

**Exporting a profile.** The inspector can write what it saw of a client as a Chameleon.Net profile in C#, in the style of
the built-in ones. Open `https://localhost:8443/capture` in a browser (accept the certificate first). The page makes the
requests an export needs:
- a navigation, a `fetch()` GET and POST, and a WebSocket over TLS;
- a navigation and a `fetch()` over plain HTTP/1.1, for header casing and the headers sent only over HTTP/2.

It ends on the exported profile, ready to copy or download. For other clients, such as an app on a phone, `/profiles`
lists every client seen (address and `User-Agent`), and `/profile/{id}` exports one of them. What a client didn't show is
listed in comments at the top of the file, for example no WebSocket or only one TLS connection (so Chrome's shuffle
can't be detected). Review those before using the profile.

The tests run every built-in profile through the inspector over loopback, for HTTP/2, HTTP/1.1 and WebSockets. They
also export each one, compile the export, and check that it produces the same fingerprints as the original.

## Creating a profile

[docs/creating-a-profile.md](docs/creating-a-profile.md) covers capturing a client (packet capture, tls.peet.ws, or a
scripted headless browser), turning the capture into a profile, and verifying it.

### Automated profile updates

The `Profiles` workflow (`.github/workflows/profiles.yml`) runs every Monday:
1. It installs the latest Chrome, Edge, Firefox, Brave and Opera on GitHub's Windows, macOS and Linux runners, and Safari
   on macOS.
2. It opens each one at the inspector's `/capture` page (`eng/profile-capture/Capture.ps1`). Browsers run with a visible
   window, under a virtual display on Linux, because headless browsers identify themselves.
3. For every version that isn't built in yet, it opens a pull request (`eng/profile-capture/Propose.ps1`). The pull
   request adds the profile and points its "latest" alias at it, and the offline tests put it through the inspector
   end to end.
4. The pull request description lists the fingerprints, the inspector's findings, what the capture couldn't observe,
   and the changes from the previous version. Nothing is merged without a review.

It can also be started by hand from the Actions tab, for a subset of captures (`only: chrome:windows,firefox:linux`).

Setup:
- Allow GitHub Actions to create pull requests (Settings → Actions → General → Workflow permissions).
- Optionally, add a `PROFILE_BOT_TOKEN` secret: a fine-grained token with contents and pull request write access.
  Pull requests opened with the default `GITHUB_TOKEN` don't trigger CI. The workflow runs the build and tests itself
  either way.

Locally, `./eng/profile-capture/Capture.ps1 -Browser edge -SkipInstall -NoTrust` captures the installed Edge without
changing the machine.

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

## Versioning and releases

Versions come from git tags, through [MinVer](https://github.com/adamralph/minver), following
[semantic versioning](https://semver.org/). Nothing in the repository holds a version number.

- A commit tagged `v1.2.3` builds as `1.2.3`, and `v1.2.3-preview.1` as `1.2.3-preview.1`.
- Commits after the latest tag build as the next patch preview, e.g. `1.2.4-preview.0.5` five commits after `v1.2.3`.
  Before any tag it's `0.0.0-preview.0.N`.

To release, tag the commit and push the tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The `Release` workflow then builds, tests, packs, publishes the packages to nuget.org and creates a GitHub release with
the packages attached (marked as pre-release when the version has a suffix). It publishes through nuget.org
[trusted publishing](https://learn.microsoft.com/nuget/nuget-org/trusted-publishing), so no API key is stored. Both packages
(`Chameleon.Net` and `Chameleon.Net.Extensions.Http`) are released together, with the same version. Publishing needs
a trusted publishing policy on nuget.org for this repository and `release.yml`, and a `NUGET_USER` repository secret
with the nuget.org user name.

## License

[MIT](LICENSE).
