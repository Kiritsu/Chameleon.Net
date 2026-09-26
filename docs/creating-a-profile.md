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
| 13 | `SignatureAlgorithmsExtension` | scheme ids in order (`tls.handshake.sig_hash_alg`) |
| 16 | `AlpnExtension` | protocol strings in order |
| 18 | `SignedCertificateTimestampExtension` | none |
| 21 | `PaddingExtension` | see §3.3 |
| 23 | `ExtendedMasterSecretExtension` | none |
| 27 | `CompressCertificateExtension` | algorithm ids (2 = brotli, 1 = zlib) |
| 28 | `RecordSizeLimitExtension` | the limit |
| 34 | `DelegatedCredentialsExtension` | scheme ids |
| 35 | `SessionTicketExtension` | none on a fresh connection |
| 43 | `SupportedVersionsExtension` | versions in order; drop GREASE, set `GreasePlacement.SupportedVersions` |
| 45 | `PskKeyExchangeModesExtension` | modes (`[1]` = psk_dhe_ke) |
| 51 | `KeyShareExtension` | the **groups** that carry a key share, in order (not the key bytes); drop GREASE, set `GreasePlacement.KeyShare` |
| 17513 | `ApplicationSettingsExtension` | ALPS protocol list |
| 65037 | `EncryptedClientHelloGreaseExtension` | none — Chrome's GREASE ECH |
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

- **GREASE values** — drawn from the 16 reserved values each time. Only the *placement* is data.
- **Chrome extension order** — since Chrome 110 it is shuffled per connection, with GREASE pinned
  first/last and padding last. Set `ExtensionShufflePolicy.Chrome` and write the extensions in any
  one captured order, keeping the leading `GreaseExtension` first and the trailing
  `GreaseExtension` + `PaddingExtension` last — the encoder only shuffles what lies between them.
  JA3 for Chrome is inherently unstable; JA4 (sorted) is what you match.
- **`key_share` public keys, `client_random`, `session_id`** — generated per connection.
- **`pre_shared_key` (41)** on a *second* connection to the same host. Capture fresh connections
  (restart the client, or use a host it has not seen). Session resumption is out of scope for v1.
- **`session_ticket` body** — present and empty on a fresh connection.

### 3.5 Check what BouncyCastle can actually negotiate

Listing an extension is not the same as surviving the server's reply to it. None of the following
is handled by Chameleon.Net yet; a profile that relies on them will emit the right fingerprint but
can fail the handshake:

- `compress_certificate` (27): the server may answer with a compressed Certificate message;
  BouncyCastle 2.6 does not decode it.
- `X25519MLKEM768` (0x11EC = 4588) in `key_share`: BouncyCastle 2.6 has ML-KEM but not the
  hybrid group; it needs a custom agreement. Listing it in `supported_groups` only, without a
  share, risks a HelloRetryRequest for it.
- ALPS (17513) and ECH (65037): the server can answer them in EncryptedExtensions, which
  BouncyCastle does not expect.

Note these in the profile's remarks, and run the live handshake (§7) against the real target.

## 4. HTTP/2 preface → `Http2Profile`

This is inside the TLS session, so a capture needs decryption — or the library source.

**Browsers**: set `SSLKEYLOGFILE` before starting Chrome/Firefox, point Wireshark at it
(*Preferences → Protocols → TLS → (Pre)-Master-Secret log*), then filter `http2`. Read, in order,
the first frames the client sends after the connection preface:

- `http2.type == 4` SETTINGS: identifier/value pairs **in the order written** → `Http2SettingsFrame`
- `http2.type == 8` WINDOW_UPDATE on stream 0: increment → `Http2WindowUpdateFrame`
- `http2.type == 2` PRIORITY frames (Firefox sends several for streams 3–13) → `Http2PriorityFrame`
- first `http2.type == 1` HEADERS: pseudo-header order (`http2.header.name` starting with `:`) →
  `PseudoHeaderOrder`, and its priority fields if the PRIORITY flag is set → `Http2HeadersPriority`

**Android apps** cannot be key-logged, and a MITM proxy replaces the H2 stack. Two honest options:

1. If you can point the app at a server you control, log the frames there (nghttp2's `nghttpd -v`
   prints every frame).
2. Otherwise read the HTTP library's source. For OkHttp this is `Http2Connection.start()` and
   `Http2Writer.settings()` (note the index remap: `INITIAL_WINDOW_SIZE` is stored at index 7 but
   written as id 4, after `MAX_FRAME_SIZE`). Mark such values as *derived from source, not
   captured* in the remarks — they are the first thing to verify when a capture becomes possible.

Compute the Akamai string from what you found and record it next to the JA3/JA4 as an expected
value: `settings|window_update|priorities|pseudo-header letters`, e.g. `5:16384;4:16777216|16711681|0|m,p,a,s`.

## 5. Headers → `HeaderProfile`

Header **order** is what JA4H hashes (the Akamai fingerprint only covers pseudo-headers, §4);
casing only matters on HTTP/1.1 (HTTP/2 lowercases everything).

- Browsers: the decrypted HTTP/2 capture from §4 already shows the order. Capture one request of
  each kind you care about (a navigation, a `fetch()`, an XHR) — they differ — and fill
  `Overrides` per `RequestKind`. `HeaderOrder` is the fallback.
- Native clients: the order is deterministic from the library. OkHttp's `BridgeInterceptor`
  appends `Content-Type`, `Content-Length`/`Transfer-Encoding`, `Host`, `Connection`,
  `Accept-Encoding`, `Cookie`, `User-Agent` after whatever the app set, in that order. Leave
  `Overrides` empty.

`DefaultHeaders` are the values the client sends when the caller sets nothing: `User-Agent`,
`Accept`, `Accept-Language`, `Accept-Encoding`, `Sec-CH-UA*` for Chromium. Only advertise an
`Accept-Encoding` the HTTP layer can decode (`gzip, deflate, br, zstd` for Chrome).

For an *app-specific* profile (an app on top of OkHttp), copy the app's own `User-Agent` and
extra headers here; the TLS and H2 layers stay those of the library.

## 6. WebSocket handshake → `WebSocketProfile`

Capture (or read) the Upgrade request:

- header order → `HandshakeHeaderOrder`
- the literal `Sec-WebSocket-Extensions` value → `PerMessageDeflateOffer`
  (Chrome: `permessage-deflate; client_max_window_bits`; OkHttp ≥ 4.9: `permessage-deflate`;
  null if the client does not offer compression)
- ALPN on WebSocket connections, if it differs from ordinary requests → `Alpn`
  (OkHttp forces `http/1.1`; recent Chrome and Firefox offer `h2` and may do RFC 8441)

## 7. Verify before shipping

1. Put the expected `ja3_full`, `ja4_r` and Akamai strings in the profile's `<summary>`.
2. Add a golden test next to `tests/Chameleon.Net.Tests/Tls/OkHttp4Android13GoldenTests.cs`:
   `ClientHelloCapture.CaptureAsync` runs the real pipeline offline, then
   `ClientHelloParser.Parse` + `TlsFingerprinter.Compute` produce the strings to assert. For
   shuffled/GREASE profiles assert JA4/JA4_r (stable), not JA3.
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
| H2 preface | `Http2Connection.start()` / `Http2Writer.settings()` — derived from source | `5:16384;4:16777216\|16711681\|0\|m,p,a,s` |
| Header order | `BridgeInterceptor` | `HeaderOrder`, no overrides |
| WebSocket | `RealWebSocket.connect()` | header order, `permessage-deflate` |
