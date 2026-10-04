# Creating a profile from scratch

A `ClientProfile` is a data description of what a real client puts on the wire. Nothing in it is
invented: every value comes from a capture of the real client, or from reading the source of the
library that produces it. This page walks through the research, layer by layer, and maps each
finding onto the records in `Chameleon.Net.Profiles`.

Order of work: **TLS first** (it decides whether you connect at all), then HTTP/2, then headers,
then WebSocket. Write down where each value came from — profiles rot with every client release
and the next person needs to know what to re-capture.

## 1. Pick the target precisely

"Chrome on Android" is not a target. A fingerprint is a function of:

- the client library and version (Chrome 131, OkHttp 4.12, Firefox 128, Cronet, Flutter/dart:io…),
- the TLS stack under it (BoringSSL, Conscrypt, NSS, SecureTransport, Schannel) and its version,
- the OS version (Android 13 ships a different Conscrypt than Android 10),
- sometimes the request kind (browsers shape navigation, fetch, XHR and WebSocket requests differently).

`ProfileIdentity` holds the platform, client family and version; write the TLS stack and OS
version in the profile's `<summary>`. If you cannot pin the tuple, the profile will still "work"
until the day a detection vendor compares it against the version claimed in the User-Agent.

## 2. Capture the ClientHello

The ClientHello is plaintext. Any packet capture works; no MITM, no key logging.

**Desktop browser or CLI client** — run Wireshark (or `tshark`) on the machine, open a page, filter:

```
tls.handshake.type == 1
```

**Android app** — three options, from least to most invasive:

1. Route the phone through a laptop hotspot and capture on the laptop.
2. PCAPdroid (no root; VPN-based) and export the `.pcap`.
3. `adb shell tcpdump` on an emulator or rooted device.

Do **not** capture through a MITM proxy (mitmproxy, Charles, Burp): the ClientHello you see is
the proxy's, not the app's. The same applies to everything below the HTTP layer.

Wireshark computes the fingerprints for you (≥ 4.2 for JA4):

```
tshark -r capture.pcapng -Y "tls.handshake.type == 1" -T fields \
  -e tls.handshake.extensions_server_name \
  -e tls.handshake.ja3_full -e tls.handshake.ja3 \
  -e tls.handshake.ja4 -e tls.handshake.ja4_r
```

Keep `ja3_full` and `ja4_r`: they are the human-readable forms and become the expected values in
the profile's golden test.

Capture **several** connections to the same host and diff them. What varies between captures is
not profile data (see §3.4).

**Browsers, without Wireshark** — this is how `Chromium152Windows` was built:

1. Open `https://tls.peet.ws/api/all` in the browser. The JSON lists every ClientHello extension
   *with its data* (groups, key shares, signature algorithms, ALPS, ECH), the HTTP/2 frames the
   browser sent (SETTINGS, WINDOW_UPDATE, HEADERS with priority and header order) and the
   JA3/JA4/Akamai strings to put in the golden test.
2. From the devtools console of that page, `fetch("/api/all")` (and a POST) and read the echoed
   HEADERS frame: that's the `RequestKind.Fetch` header order and defaults, which differ from a
   navigation's.
3. For HTTP/1.1 casing and the WebSocket handshake, serve a page from a local plain-HTTP server
   that logs raw request heads, and have it fire a `fetch()`, a POST and a `new WebSocket(...)`.

Use a fresh browser session: a second connection to the same host may resume the TLS session and
carry `pre_shared_key` (41), which changes JA4 (see §3.4).

**Installed browsers, scripted** — this is how `Firefox156Windows` was built. Start the browser
headless with a throwaway profile directory and a remote-debugging port
(`firefox --headless --no-remote --profile <empty dir> --remote-debugging-port 9333`), connect to
`ws://127.0.0.1:9333/session` (WebDriver BiDi), then `browsingContext.navigate` to the pages above
and `script.evaluate` `document.body.innerText` or a `fetch(...)`. Set
`user_pref("devtools.jsonview.enabled", false)` in the profile's `user.js` so the JSON comes back as
text. Launch it several times: each launch is a fresh TLS session, and the diff shows what varies.
Chromium-based browsers (Chrome, Edge) work the same way over the Chrome DevTools Protocol, which is how
`Edge153Windows` was built: `msedge --headless=new --user-data-dir=<empty dir> --remote-debugging-port=9444`,
then `Page.navigate` and `Runtime.evaluate` on the page target listed at `http://127.0.0.1:9444/json/list`.
Headless doesn't change the TLS or HTTP/2 layers, but check the User-Agent (headless Chromium says
`HeadlessChrome`).

## 3. Read the ClientHello into `TlsProfile`

Open one ClientHello in Wireshark's packet details. Everything you need is under
`Handshake Protocol: Client Hello`.

### 3.1 Cipher suites → `TlsProfile.CipherSuites`

Copy the list in wire order as decimal ids (`tls.handshake.ciphersuite`). Keep the order exactly:
JA3 is order-sensitive. (JA4 sorts the list before hashing, so it only sees the set.)

If the first entry is a GREASE value (`0x?a?a` — 2570, 6682, 10794, …), drop it from the list and
set `GreasePlacement.CipherSuites`. The encoder re-injects a fresh GREASE value on every
connection, as BoringSSL does.

### 3.2 Extensions → `TlsProfile.Extensions`

List the extension **types** in wire order (`tls.handshake.extension.type`). For each one create the
matching record, in that order:

| Type | Record | Data to copy from the capture |
|---|---|---|
| 0 | `ServerNameExtension` | none — host comes from the connection |
| 5 | `StatusRequestExtension` | none |
| 10 | `SupportedGroupsExtension` | group ids in order; drop GREASE, set `GreasePlacement.SupportedGroups` |
| 11 | `EcPointFormatsExtension` | formats (almost always `[0]`) |
| 13 | `SignatureAlgorithmsExtension` | scheme ids in order (`tls.handshake.sig_hash_alg`); drop a leading GREASE, set `GreasePlacement.SignatureAlgorithms` |
| 16 | `AlpnExtension` | protocol strings in order |
| 18 | `SignedCertificateTimestampExtension` | none |
| 21 | `PaddingExtension` | see §3.3 |
| 23 | `ExtendedMasterSecretExtension` | none |
| 27 | `CompressCertificateExtension` | algorithm ids (2 = brotli, 1 = zlib, 3 = zstd) |
| 28 | `RecordSizeLimitExtension` | the limit |
| 34 | `DelegatedCredentialsExtension` | scheme ids |
| 35 | `SessionTicketExtension` | none on a fresh connection |
| 43 | `SupportedVersionsExtension` | versions in order; drop GREASE, set `GreasePlacement.SupportedVersions` |
| 45 | `PskKeyExchangeModesExtension` | modes (`[1]` = psk_dhe_ke) |
| 51 | `KeyShareExtension` | the **groups** that carry a key share, in order (not the key bytes); drop GREASE, set `GreasePlacement.KeyShare` |
| 17513 / 17613 | `ApplicationSettingsExtension` | ALPS protocol list; pass `Codepoint: 17613` for the new codepoint (Chrome 131+) |
| 65037 | `EncryptedClientHelloGreaseExtension` | GREASE ECH. Defaults are BoringSSL's (AES-128-GCM, payload 144/176/208/240); for NSS pass `AeadIds: [0x0001, 0x0003], PayloadLengths: [240]`. Read the AEAD (bytes 3–4) and payload length from several captures |
| 65281 | `RenegotiationInfoExtension` | none |
| `0x?a?a` | `GreaseExtension` | the body, copied from the capture (BoringSSL: first empty, last one byte `0x00`); keep it at the position it sat — the value is drawn per connection |
| anything else | `RawExtension(type, body)` | copy the raw body bytes |

`SupportedGroups`, `SignatureAlgorithms`, `SupportedVersions`, `Alpn` and `KeyShare` live inside
their extension records — there is no duplicate list on `TlsProfile`. The single source of truth
is the ordered extension list.

### 3.3 Padding

BoringSSL-based clients (Chrome, Android, Cronet) add a `padding` extension only when the
unpadded ClientHello handshake message is between 256 and 511 bytes, and pad it to exactly 512.
That is what `PaddingExtension(TargetClientHelloLength: 512)` means; the encoder applies the rule,
and outside that range the extension is simply not emitted. The consequence: the same profile can
produce a fingerprint with or without `21` depending on the hello's size (hostname, key shares,
extra extensions). That is correct behaviour — the real client does the same.

Other stacks have their own rules. Only add the record if `21` shows up in your captures, and
check that it appears (or not) at the same hello sizes.

### 3.4 What is *not* profile data

Diff two captures of the same client. These change per connection and are handled by the
encoder or by BouncyCastle, never written into the profile:

- **GREASE values** — drawn from the 16 reserved values for each connection. Only the *placement* is data.
  The encoder keeps them fixed for the whole connection (a ClientHello retried after HelloRetryRequest
  reuses them, and leaves out the GREASE key share), and gives `key_share` the same GREASE group as
  `supported_groups`, as BoringSSL does.
- **Chrome extension order** — since Chrome 110 it is shuffled per connection, with GREASE pinned
  first/last and padding last. Set `ExtensionShufflePolicy.Chrome` and write the extensions in any
  one captured order, keeping the leading `GreaseExtension` first and the trailing
  `GreaseExtension` + `PaddingExtension` last — the encoder only shuffles what lies between them.
  JA3 for Chrome is inherently unstable; JA4 (sorted) is what you match.
- **`key_share` public keys, `client_random`, `session_id`** — generated per connection.
- **`pre_shared_key` (41)** on a *second* connection to the same host. Capture fresh connections
  (restart the client, or use a host it has not seen). Don't list it in the profile: when a profile
  has `PskKeyExchangeModesExtension`, Chameleon.Net resumes with tickets from earlier connections
  (like BoringSSL, each ticket once) and appends `pre_shared_key` last on its own
  (`ChameleonOptions.TlsSessionResumption` turns this off).
- **`session_ticket` body** — present and empty on a fresh connection.
- **GREASE ECH AEAD and payload length** — picked per connection: BoringSSL uses AES-128-GCM and 144,
  176, 208 or 240 bytes, NSS AES-128-GCM or ChaCha20-Poly1305 and always 240. Only the choices are
  data (`EncryptedClientHelloGreaseExtension` parameters, §3.2).

### 3.5 Check what the handshake layer can negotiate

Listing an extension is not the same as surviving the server's reply to it. Chameleon.Net fills
these BouncyCastle 2.6 gaps itself, each checked live against Cloudflare and Google:

- `X25519MLKEM768` (0x11EC = 4588), `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` key shares.
- `compress_certificate` (27) with brotli (2), zlib (1) or zstd (3).
- ALPS (17513 / 17613): when the server accepts it, the client answers with its (empty) settings
  before Finished, as BoringSSL does.
- GREASE ECH (65037): the server's retry configs in EncryptedExtensions are accepted and ignored.
- TLS 1.3 session resumption: tickets from NewSessionTicket are kept and offered on later connections
  (`pre_shared_key` with a resumption binder), which BouncyCastle doesn't do on its own.
- HelloRetryRequest: the second ClientHello keeps the first one's GREASE values and extension order.
  A retry that asks for a hybrid post-quantum group the profile lists without a key share isn't
  supported, so send the hybrid share whenever you list the group.

Anything else new: run the live handshake (§7) against the real target before trusting it.

## 4. HTTP/2 preface → `Http2Profile`

This is inside the TLS session, so a capture needs decryption — or the library source.

**Browsers**: set `SSLKEYLOGFILE` before starting Chrome/Firefox, point Wireshark at it
(*Preferences → Protocols → TLS → (Pre)-Master-Secret log*), then filter `http2`. Read, in order,
the first frames the client sends after the connection preface:

- `http2.type == 4` SETTINGS: identifier/value pairs **in the order written** → `Http2SettingsFrame`
- `http2.type == 8` WINDOW_UPDATE on stream 0: increment → `Http2WindowUpdateFrame`
- `http2.type == 2` PRIORITY frames (older Firefox sent several for streams 3–13; Firefox 156 sends none) → `Http2PriorityFrame`
- first `http2.type == 1` HEADERS: pseudo-header order (`http2.header.name` starting with `:`) →
  `PseudoHeaderOrder`, and its priority fields if the PRIORITY flag is set → `Http2HeadersPriority`
  (the record takes the wire weight, i.e. what tls.peet.ws shows minus 1). Chrome's weight follows
  the request's urgency — 256 for a navigation, 220 for a `fetch()` — so put the per-kind values in
  `HeadersPriorityOverrides`.
- the stream id of that first HEADERS → `FirstStreamId` (Firefox uses 3, everyone else 1).
- with two cookies or more, whether the request carries one `cookie` field per cookie →
  `Hpack: new HpackProfile(SplitCookies: true)` (Chrome, every Chromium-based browser, Safari), or
  one joined field (OkHttp; leave `Hpack` out).
- which HPACK indexing rules the client follows → `HpackProfile.Indexing`: `OkHttp` (OkHttp and
  Chrome) or `Nghttp2` (Safari: cookies under 20 bytes never indexed, `content-length` not indexed).
  The Inspector reports each field's HPACK representation, replays the connection's header blocks
  through the reference profile's rules to flag a difference, and picks the rules when exporting.
  It judges cookies and HPACK only against profiles with `Hpack` set (and OkHttp's), so set it,
  even to `new HpackProfile()`, once you have checked the client's header blocks.

tls.peet.ws (§2) shows all of this without key logging.

**Android apps** cannot be key-logged, and a MITM proxy replaces the H2 stack. Two honest options:

1. If you can point the app at a server you control, log the frames there (nghttp2's `nghttpd -v`
   prints every frame).
2. Otherwise read the HTTP library's source. For OkHttp this is `Http2Connection.okHttpSettings` and
   `start()` (only `INITIAL_WINDOW_SIZE` is set; it is stored at index 7 and `Http2Writer.settings()`
   writes it as id 4). Mark such values as *derived from source, not captured* in the remarks —
   they are the first thing to verify when a capture becomes possible.

Record the expected Akamai string next to the JA3/JA4: `AkamaiFingerprint.Compute(profile.Http2)`
gives `settings|window_update|priorities|pseudo-header letters`, e.g. `4:16777216|16711681|0|m,p,a,s`.

## 5. Headers → `HeaderProfile`

Header **order** is what JA4H hashes (the Akamai fingerprint only covers pseudo-headers, §4);
casing only matters on HTTP/1.1 (HTTP/2 lowercases everything).

- Browsers: the decrypted HTTP/2 capture from §4 already shows the order. Capture one request of
  each kind you care about (a navigation, a `fetch()`, an XHR) — they differ — and fill
  `Overrides` per `RequestKind`. `HeaderOrder` is the fallback.
- Native clients: the order is deterministic from the library. OkHttp's `BridgeInterceptor`
  appends `Content-Type`, `Content-Length`/`Transfer-Encoding`, `Host`, `Connection`,
  `Accept-Encoding`, `Cookie`, `User-Agent` after whatever the app set, in that order — but only
  the ones the app didn't set: an app-set `User-Agent` stays where the app put it. Leave
  `Overrides` empty and set `OrderMode = HeaderOrderMode.CallerFirst`.

`HeaderOrderMode.ProfileOrder` (the default) is the browser behaviour: every listed header takes its
profile position, whoever set it.

`DefaultHeaders` are the values the client sends when the caller sets nothing: `User-Agent`,
`Accept`, `Accept-Language`, `Accept-Encoding`, `Sec-CH-UA*` for Chromium. Browsers send different
defaults per request kind (a navigation's `Accept`/`Sec-Fetch-*` vs a `fetch()`'s, and a WebSocket
handshake adds `Pragma`/`Cache-Control`): put them in `DefaultHeaderOverrides`. Headers a browser
only sends over HTTP/2 (Chrome's `priority`, Firefox's `te: trailers`) go in `Http2OnlyHeaders`.
Name casing on HTTP/1.1 comes from the spelling in the order list (`HeaderCasing.AsSpecified`):
Chrome writes `User-Agent` but `sec-ch-ua`.

Chameleon.Net decodes gzip, deflate, br and zstd when the Accept-Encoding came from the profile; if the
caller sets Accept-Encoding itself, the body is returned as sent, like OkHttp does.

For an *app-specific* profile (an app on top of OkHttp), copy the app's own `User-Agent` and
extra headers here; the TLS and H2 layers stay those of the library.

## 6. WebSocket handshake → `WebSocketProfile`

Capture (or read) the Upgrade request:

- header order → `HandshakeHeaderOrder`
- the literal `Sec-WebSocket-Extensions` value → `PerMessageDeflateOffer`
  (Chrome: `permessage-deflate; client_max_window_bits`; Firefox and OkHttp ≥ 4.9: `permessage-deflate`;
  null if the client does not offer compression)
- ALPN on WebSocket connections, if it differs from ordinary requests → `Alpn`
  (OkHttp forces `http/1.1`. Chrome uses `http/1.1` for WebSocket connections unless it can reuse
  an HTTP/2 connection with RFC 8441, which Chameleon.Net doesn't implement; the Chromium profile's
  `http/1.1` is assumed, not captured — the capture was over plain `ws://`)
- the handshake's own default headers → `HeaderProfile.DefaultHeaderOverrides[RequestKind.WebSocket]`

## 7. Verify before shipping

1. Put the expected `ja3_full`, `ja4_r` and Akamai strings in the profile's `<summary>`.
2. Add a golden test in `tests/Chameleon.Net.Tests/Profiles/` (see `Firefox156WindowsGoldenTests`):
   `ClientHelloCapture.CaptureAsync` runs the real pipeline offline, then
   `ClientHelloParser.Parse` + `TlsFingerprinter.Compute` produce the strings to assert. For
   profiles with Chrome's extension shuffle assert JA4/JA4_r (stable), not JA3; GREASE alone doesn't
   change JA3, which leaves GREASE values out.
3. Against the network: connect to an echo service that reports JA3/JA4/Akamai as observed
   (tls.peet.ws is the common one) and compare with the real client's result on the *same*
   service. Treat third-party echo services as a spot check, not a test dependency.
4. Against the real target: the handshake must complete (§3.5) — matching the hash is worthless
   if the connection fails on the server's reply. `LiveHandshakeTests` shows the pattern; run it
   with `dotnet test --solution Chameleon.Net.slnx -- --explicit only`.

## 8. Where it goes

Built-in profiles are C# data in `src/Chameleon.Net/Profiles/BuiltIn/<Name>.cs`, one file per
profile, as a property on the partial `BuiltInProfiles` class. The `<summary>` carries the
expected fingerprint strings and the capture provenance (client build, OS, date, method).
`IProfileSerializer` is the contract for loading captured profiles at runtime; it has no
implementation or file format yet.

## Worked example: `BuiltInProfiles.OkHttp4Android13`

Nothing in this profile has been captured from a device yet. Its TLS layer matches the published
tls-client JA3 (asserted in `OkHttp4Android13GoldenTests`); everything else is derived from source
and is the first thing to verify once a capture is available.

| Layer | Source | Result |
|---|---|---|
| Cipher suites, extension order, groups, point formats | tls-client's `okhttp4_android_13` spec | JA3 `771,4865-…-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0` |
| Signature algorithms | BoringSSL defaults (Conscrypt), 9 entries ending in `rsa_pkcs1_sha1` — not captured | JA4_r last segment `0403,0804,0401,0503,0805,0501,0806,0601,0201` |
| ALPN | OkHttp `Protocol` list `h2, http/1.1`; `RealWebSocket` forces `http/1.1` | `AlpnExtension`, `WebSocketProfile.Alpn` |
| Padding | BoringSSL rule | `PaddingExtension(512)` |
| H2 preface | `Http2Connection.okHttpSettings` / `start()`, checked against the 4.12.0 source | `4:16777216\|16711681\|0\|m,p,a,s` |
| HPACK | `Hpack.Writer`: indexing choices, Huffman when shorter, table up to 16 KiB | `HpackEncoder` (not profile data) |
| Header order | `BridgeInterceptor` | `HeaderOrder`, no overrides, `CallerFirst` |
| WebSocket | `RealWebSocket.connect()` | header order, `permessage-deflate` |

## Worked example: `BuiltInProfiles.Chromium152Windows`

Captured on 2026-09-26 from Chromium 152.0.7977.130 on Windows with the browser method of §2.
`Chromium152WindowsGoldenTests` replays every capture offline, and the explicit
`EchoServiceSeesTheChromiumCapture` test checks that tls.peet.ws reports the same JA4, Akamai
fingerprint and HEADERS priority for Chameleon.Net as it did for the browser.

| Layer | Source | Result |
|---|---|---|
| ClientHello | tls.peet.ws `/api/all` | JA4 `t13d1516h2_8daaf6152771_806a8c22fdea`, Chrome shuffle, GREASE in 5 places |
| HTTP/2 | tls.peet.ws `sent_frames` | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p`; weight 256 navigation / 220 fetch |
| Fetch headers | `fetch()` from the tls.peet.ws page, and from a local page over HTTP/1.1 | `HeaderOrder`, `DefaultHeaders` |
| Navigation headers | the page load itself (HTTP/2 and HTTP/1.1) | `Overrides[Navigate]`, `DefaultHeaderOverrides[Navigate]` |
| WebSocket | `new WebSocket(...)` from the local page | `HandshakeHeaderOrder`, `DefaultHeaderOverrides[WebSocket]` |
| Not observed | client hints on navigations, Cookie positions, WebSocket ALPN | placed from Chrome's known behaviour; the order of client hints and Cookie was later confirmed on Edge 153 (`BuiltInProfiles.Edge153Windows`, same stack, captured with the scripted method over CDP) |
| Adjusted | app-specific User-Agent tokens, the capturing user's Accept-Language | generic values |

## Worked example: `BuiltInProfiles.Firefox156Windows`

Captured on 2026-09-26 from Firefox 156.0.1 on Windows with the scripted method of §2 (headless,
three fresh launches). `Firefox156WindowsGoldenTests` replays the captures offline, and the explicit
`EchoServiceSeesTheFirefoxCapture` test checks that tls.peet.ws reports the same JA3, JA4, Akamai
fingerprint, first stream id and HEADERS priority for Chameleon.Net as it did for the browser.

| Layer | Source | Result |
|---|---|---|
| ClientHello | tls.peet.ws `/api/all`, 3 launches | JA3 `9d42e90b0225e779f03141ddcd699df2` (stable: NSS neither shuffles nor GREASEs), JA4 `t13d1517h2_8daaf6152771_3cbfd9057e0d`; three key shares (X25519MLKEM768, X25519, P-256); GREASE ECH with a random AEAD and a 240-byte payload |
| HTTP/2 | tls.peet.ws `sent_frames` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s`; first request on stream 3; weight 42 navigation / 22 fetch, not exclusive; `te: trailers` only on HTTP/2 |
| Fetch, navigation, cookies | local page over HTTP/1.1 (the page sets a cookie) | one `HeaderOrder` fits every kind; Cookie right after Connection |
| WebSocket | `new WebSocket(...)` from the local page | `HandshakeHeaderOrder`; Sec-Fetch-Mode `websocket`; plain `permessage-deflate` |
| Not supported | delegated credentials | offered like Firefox does; Cloudflare, Google, GitHub, mozilla.org and example.com don't use them on it |

## Worked example: `BuiltInProfiles.Edge153Windows`

Captured on 2026-09-26 from Edge 153.0.4234.48 on Windows with the scripted method of §2 (CDP,
headless, three fresh launches). Below the brand strings it is the same client as Chromium 152, so
it reuses the Chromium profile's TLS, HTTP/2, header-order and WebSocket builders and only passes
its own User-Agent, `sec-ch-ua` brands and navigation client hints. `Edge153WindowsGoldenTests` and
the explicit `EchoServiceSeesTheEdgeCapture` test check it like the others.

| Layer | Source | Result |
|---|---|---|
| ClientHello, HTTP/2 | tls.peet.ws, 3 launches | identical to Chromium 152: JA4 `t13d1516h2_8daaf6152771_806a8c22fdea`, same Akamai string; a resumed connection showed `t13d1517h2_8daaf6152771_a87ad97598a9` |
| Headers | tls.peet.ws and a local page over HTTP/1.1 (setting a cookie) | `"Microsoft Edge";v="153", …` brands; client hints on navigations; Cookie after Accept-Language |
| Adjusted | headless `HeadlessChrome/153` User-Agent token, the capturing machine's Accept-Language | `Chrome/153`, generic Accept-Language |
