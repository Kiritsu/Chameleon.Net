using System.Globalization;
using System.Text;
using Chameleon.Net.Inspector.Analysis;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Inspector.Tls;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Export;

/// <param name="AliasName">The per-browser, per-OS "latest" alias this profile becomes the target of, e.g. <c>ChromeWindows</c>.</param>
/// <param name="Notes">What couldn't be observed and was guessed or left out, for the exported file's comments.</param>
internal sealed record ExportedProfile(ClientProfile Profile, string PropertyName, string AliasName, IReadOnlyList<string> Notes, ExportFingerprints Fingerprints);

/// <param name="Ja3Hash">Of the connection the TLS profile was taken from; it changes per connection when the extensions are shuffled.</param>
internal sealed record ExportFingerprints(string Ja4, string Ja3Hash, string? Akamai);

/// <summary>Builds a <see cref="ClientProfile"/> from everything one client showed the inspector. Each part comes from what was
/// observed: the ClientHello of a fresh (non-resumed) connection, the HTTP/2 preface, and the headers of each request kind, told
/// apart by Sec-Fetch-Mode. The more kinds of request the client made (see <c>/capture</c>), the more complete the profile.</summary>
internal static class ProfileExporter
{
    /// <summary>Request-specific headers: positioned by the header order, never sent as defaults.</summary>
    private static readonly HashSet<string> NotDefaults = new(StringComparer.OrdinalIgnoreCase)
    {
        "host", "content-length", "content-type", "transfer-encoding", "cookie", "referer", "origin", "authorization", "upgrade",
        "sec-websocket-key", "sec-websocket-version", "sec-websocket-extensions", "sec-websocket-protocol",
    };

    private static readonly int[] BoringSslEchPayloadLengths = [144, 176, 208, 240];

    private sealed record Seen(ConnectionCapture Connection, RequestCapture Request, RequestKind Kind)
    {
        public bool Http2 => Request.Version == "2";
    }

    /// <param name="product">Names the client instead of its User-Agent: Brave's is identical to Chrome's.</param>
    /// <exception cref="InvalidOperationException">Nothing from this client went over TLS.</exception>
    public static ExportedProfile Export(ClientSnapshot client, string? product = null)
    {
        var tlsConnections = client.Observations.Select(static o => o.Connection).Where(static c => c.Hello is not null).Distinct().ToList();
        if (tlsConnections.Count == 0)
        {
            throw new InvalidOperationException("This client hasn't made a TLS connection: a profile starts from its ClientHello.");
        }

        var notes = new List<string>();
        var userAgent = UserAgentParser.Parse(client.UserAgent);
        var requests = client.Observations.Where(static o => o.Request is not null)
            .Select(static o => new Seen(o.Connection, o.Request!, KindOf(o.Request!)))
            .ToList();
        notes.Add(Summary(tlsConnections.Count, requests));

        var main = tlsConnections.FirstOrDefault(static c => c.Hello!.Alpn.Contains("h2") && c.Hello.PreSharedKey is null)
            ?? tlsConnections.FirstOrDefault(static c => c.Hello!.PreSharedKey is null)
            ?? tlsConnections[0];
        var spellings = Spellings(requests);
        var tls = ExportTls(main, tlsConnections, notes);
        var (http2, akamai) = ExportHttp2(client.Observations, requests, notes);
        var headers = ExportHeaders(requests, spellings, userAgent, notes);
        var webSocket = ExportWebSocket(requests, tls, notes);
        var identity = Identity(userAgent, product);
        return new ExportedProfile(
            new ClientProfile(identity, tls, http2, headers, webSocket),
            PascalCase($"{identity.ClientFamily}_{identity.Version}") + identity.Platform,
            PascalCase(identity.ClientFamily) + identity.Platform,
            notes,
            new ExportFingerprints(main.Fingerprint!.Ja4, main.Fingerprint.Ja3Hash, akamai));
    }

    public static RequestKind KindOf(RequestCapture request) =>
        request.WebSocket ? RequestKind.WebSocket
        : string.Equals(request.Header("sec-fetch-mode"), "navigate", StringComparison.OrdinalIgnoreCase) ? RequestKind.Navigate
        : RequestKind.Fetch;

    private static TlsProfile ExportTls(ConnectionCapture main, List<ConnectionCapture> connections, List<string> notes)
    {
        var hello = main.Hello!;

        var extensions = new List<TlsExtension>();
        foreach (var extension in hello.Extensions)
        {
            if (Extension(extension, main, connections, notes) is { } exported)
            {
                extensions.Add(exported);
            }
        }

        var grease = GreasePlacement.None;
        grease |= hello.CipherSuites.Any(TlsNames.IsGrease) ? GreasePlacement.CipherSuites : 0;
        grease |= hello.SupportedGroups.Any(TlsNames.IsGrease) ? GreasePlacement.SupportedGroups : 0;
        grease |= hello.KeyShares.Any(static k => TlsNames.IsGrease(k.Group)) ? GreasePlacement.KeyShare : 0;
        grease |= hello.SupportedVersions.Any(TlsNames.IsGrease) ? GreasePlacement.SupportedVersions : 0;
        grease |= hello.SignatureAlgorithms.Any(TlsNames.IsGrease) ? GreasePlacement.SignatureAlgorithms : 0;

        var shuffled = connections.Any(static c => c.ExtensionOrder is { DistinctOrders: > 1 });
        if (!shuffled && connections.Max(static c => c.ExtensionOrder?.Connections ?? 1) < 2)
        {
            notes.Add("Only one connection with this ClientHello was seen, so a per-connection extension shuffle (Chrome's) couldn't be detected: Shuffle is None.");
        }

        if (hello.PreSharedKey is not null)
        {
            notes.Add("Every connection seen was resumed: the ClientHello comes from a resumption, with pre_shared_key left out.");
        }

        return new TlsProfile([.. hello.CipherSuites.Where(static c => !TlsNames.IsGrease(c))], extensions,
            shuffled ? ExtensionShufflePolicy.Chrome : ExtensionShufflePolicy.None, grease);
    }

    private static TlsExtension? Extension(TlsExtensionEntry entry, ConnectionCapture main, List<ConnectionCapture> connections, List<string> notes)
    {
        var hello = main.Hello!;
        if (TlsNames.IsGrease(entry.Type))
        {
            return new GreaseExtension(entry.Data.Length == 0 ? default : entry.Data);
        }

        switch (entry.Type)
        {
            case 0: return new ServerNameExtension();
            case 5: return new StatusRequestExtension();
            case 10: return new SupportedGroupsExtension([.. hello.SupportedGroups.Where(static g => !TlsNames.IsGrease(g))]);
            case 11: return new EcPointFormatsExtension(hello.EcPointFormats);
            case 13: return new SignatureAlgorithmsExtension([.. hello.SignatureAlgorithms.Where(static s => !TlsNames.IsGrease(s))]);
            case 16: return new AlpnExtension(hello.Alpn);
            case 18: return new SignedCertificateTimestampExtension();
            case 21:
                // BoringSSL pads hellos of 256–511 bytes to 512.
                if (main.HelloLength != 512)
                {
                    notes.Add($"The padded ClientHello was {main.HelloLength} bytes, not BoringSSL's 512: check the padding target.");
                }

                return new PaddingExtension(Math.Max(512, main.HelloLength));
            case 23: return new ExtendedMasterSecretExtension();
            case 27: return new CompressCertificateExtension(hello.CertificateCompression);
            case 28: return new RecordSizeLimitExtension((ushort)hello.RecordSizeLimit!.Value);
            case 34: return new DelegatedCredentialsExtension(hello.DelegatedCredentials);
            case 35: return new SessionTicketExtension();
            case 41 or 42: return null; // Resumption is the library's: pre_shared_key and early_data are added when a ticket is used.
            case 43: return new SupportedVersionsExtension([.. hello.SupportedVersions.Where(static v => !TlsNames.IsGrease(v))]);
            case 45: return new PskKeyExchangeModesExtension(hello.PskKeyExchangeModes);
            case 51: return new KeyShareExtension([.. hello.KeyShares.Select(static k => k.Group).Where(static g => !TlsNames.IsGrease(g))]);
            case 17513 or 17613: return new ApplicationSettingsExtension(hello.AlpsProtocols, entry.Type);
            case 0xFE0D:
                var offers = connections.Select(static c => c.Hello!.Ech).OfType<EchOffer>().ToList();
                var aeads = offers.Select(static o => o.Aead).Distinct().Order().ToList();
                var lengths = offers.Select(static o => o.PayloadLength).Distinct().Order().ToList();
                if (aeads is [1] && lengths.All(BoringSslEchPayloadLengths.Contains))
                {
                    return new EncryptedClientHelloGreaseExtension();
                }

                notes.Add($"GREASE ECH: AEADs and payload lengths are the ones seen over {offers.Count} connection(s); a client may pick from more.");
                return new EncryptedClientHelloGreaseExtension(aeads, lengths);
            case 0xFF01: return new RenegotiationInfoExtension();
            default:
                notes.Add($"Extension {entry.Type} ({TlsNames.Extension(entry.Type)}) is copied as raw bytes: Chameleon.Net sends it but doesn't act on it.");
                return new RawExtension(entry.Type, entry.Data);
        }
    }

    private static (Http2Profile Profile, string? Akamai) ExportHttp2(IReadOnlyList<Observation> observations, List<Seen> requests, List<string> notes)
    {
        var capture = observations.Select(static o => o.Connection.Http2).FirstOrDefault(static c => c is not null);
        if (capture is null)
        {
            notes.Add("No HTTP/2 request was seen: the HTTP/2 part is a placeholder (empty preface).");
            return (new Http2Profile([], [PseudoHeader.Method, PseudoHeader.Authority, PseudoHeader.Scheme, PseudoHeader.Path], null), null);
        }

        var pseudo = capture.PseudoHeaders.Select(static p => p switch
        {
            ":method" => PseudoHeader.Method,
            ":authority" => PseudoHeader.Authority,
            ":scheme" => PseudoHeader.Scheme,
            ":path" => PseudoHeader.Path,
            _ => (PseudoHeader?)null,
        }).OfType<PseudoHeader>().ToList();

        var priorities = requests.Where(static r => r.Http2 && r.Kind != RequestKind.WebSocket)
            .GroupBy(static r => r.Kind)
            .ToDictionary(static g => g.Key, static g => Priority(g.First().Request.Priority));
        var baseKind = priorities.ContainsKey(RequestKind.Fetch) ? RequestKind.Fetch : priorities.Keys.FirstOrDefault();
        var basePriority = priorities.GetValueOrDefault(baseKind);
        var overrides = new Dictionary<RequestKind, Http2HeadersPriority>();
        foreach (var (kind, priority) in priorities.Where(p => p.Key != baseKind && p.Value != basePriority))
        {
            if (priority is { } value)
            {
                overrides[kind] = value;
            }
            else
            {
                notes.Add($"{kind} requests sent HEADERS without priority while {baseKind} requests had one; a profile can't express that.");
            }
        }

        return (new Http2Profile(capture.Preface, pseudo, basePriority, overrides.Count == 0 ? null : overrides, (uint)capture.FirstStreamId,
            ExportHpack(requests, notes)), capture.Akamai);
    }

    /// <summary>Cookie splitting shows only on an HTTP/2 request carrying two cookies or more: one field each, or one joined field.</summary>
    private static HpackProfile? ExportHpack(List<Seen> requests, List<string> notes)
    {
        var cookieFields = requests.Where(static r => r.Http2)
            .Select(static r => r.Request.Headers.Where(static h => h.Name.Equals("cookie", StringComparison.OrdinalIgnoreCase)).ToList())
            .Where(static fields => fields.Count > 1 || (fields.Count == 1 && fields[0].Value.Contains(';', StringComparison.Ordinal)))
            .ToList();
        if (cookieFields.Count == 0)
        {
            notes.Add("No HTTP/2 request carried two cookies: whether the client splits the Cookie header is unknown (not split).");
            return null;
        }

        return cookieFields.Any(static fields => fields.Count > 1) ? new HpackProfile(SplitCookies: true) : null;
    }

    private static Http2HeadersPriority? Priority(PriorityReport? priority) =>
        priority is null ? null : new Http2HeadersPriority((uint)priority.DependsOn, (byte)(priority.Weight - 1), priority.Exclusive);

    private static HeaderProfile ExportHeaders(List<Seen> requests, Dictionary<string, string> spellings, UserAgentReport? userAgent, List<string> notes)
    {
        var byKind = requests.GroupBy(static r => r.Kind).ToDictionary(static g => g.Key, static g => g.ToList());
        var http = byKind.Where(static k => k.Key != RequestKind.WebSocket).ToDictionary(static k => k.Key, static k => k.Value);
        if (http.Count == 0)
        {
            notes.Add("No HTTP request was seen: header order and defaults are empty.");
            return new HeaderProfile([], new Dictionary<RequestKind, IReadOnlyList<string>>(), HeaderCasing.AsSpecified, new Dictionary<string, string>());
        }

        var orders = http.ToDictionary(static k => k.Key, k => Merge(k.Value.Select(r => r.Request.Headers.Select(h => Spell(h.Name, spellings)).ToList())));
        var baseKind = http.ContainsKey(RequestKind.Fetch) ? RequestKind.Fetch : http.Keys.First();
        var baseOrder = orders[baseKind];
        var orderOverrides = orders
            .Where(o => o.Key != baseKind && !o.Value.SequenceEqual(baseOrder, StringComparer.OrdinalIgnoreCase))
            .ToDictionary(static o => o.Key, static o => o.Value);

        var baseDefaults = Defaults(http[baseKind], spellings, webSocket: false);
        var defaultOverrides = new Dictionary<RequestKind, IReadOnlyDictionary<string, string>>();
        foreach (var (kind, seen) in byKind.Where(k => k.Key != baseKind))
        {
            var defaults = Defaults(seen, spellings, kind == RequestKind.WebSocket);
            if (!defaults.SequenceEqual(baseDefaults))
            {
                defaultOverrides[kind] = defaults;
            }
        }

        // Headers a kind sent over HTTP/2 but never over HTTP/1.1 (Chrome's priority).
        var http2Only = new List<string>();
        var compared = false;
        foreach (var seen in http.Values)
        {
            var overHttp1 = seen.Where(static r => !r.Http2).SelectMany(static r => r.Request.Headers.Select(static h => h.Name)).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (overHttp1.Count == 0 || !seen.Any(static r => r.Http2))
            {
                continue;
            }

            compared = true;
            http2Only.AddRange(seen.Where(static r => r.Http2).SelectMany(static r => r.Request.Headers.Select(static h => h.Name))
                .Where(name => !overHttp1.Contains(name) && !NotDefaults.Contains(name) && !IsContextual(name))
                .Select(name => Spell(name, spellings)));
        }

        if (!compared)
        {
            notes.Add("No request kind was seen over both HTTP/1.1 and HTTP/2, so headers sent only over HTTP/2 (Chrome's priority) can't be told apart.");
        }

        if (!requests.Any(static r => !r.Http2))
        {
            notes.Add("No HTTP/1.1 request was seen: HTTP/1.1 header casing is guessed (Title-Case, sec-ch-* lowercase).");
        }

        var callerFirst = userAgent?.Family == ClientFamily.OkHttp;
        if (callerFirst)
        {
            notes.Add("OkHttp: OrderMode CallerFirst, so headers set on a request keep the caller's order, as OkHttp does.");
        }

        return new HeaderProfile(
            baseOrder,
            orderOverrides.ToDictionary(static o => o.Key, static o => (IReadOnlyList<string>)o.Value),
            HeaderCasing.AsSpecified,
            baseDefaults,
            callerFirst ? HeaderOrderMode.CallerFirst : HeaderOrderMode.ProfileOrder,
            defaultOverrides.Count == 0 ? null : defaultOverrides,
            http2Only.Count == 0 ? null : [.. http2Only.Distinct(StringComparer.OrdinalIgnoreCase)]);
    }

    private static WebSocketProfile ExportWebSocket(List<Seen> requests, TlsProfile tls, List<string> notes)
    {
        var handshake = requests.FirstOrDefault(static r => r.Kind == RequestKind.WebSocket);
        if (handshake is null)
        {
            notes.Add("No WebSocket handshake was seen: its header order is a generic guess.");
            return new WebSocketProfile(
                ["Host", "Connection", "Upgrade", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "User-Agent", "Cookie"],
                null);
        }

        var alpn = handshake.Connection.Hello?.Alpn;
        var tlsAlpn = tls.Extensions.OfType<AlpnExtension>().FirstOrDefault()?.Protocols ?? [];
        return new WebSocketProfile(
            [.. handshake.Request.Headers.Select(static h => h.Name)],
            handshake.Request.Header("sec-websocket-extensions"),
            alpn is not null && !alpn.SequenceEqual(tlsAlpn) ? alpn : null);
    }

    /// <summary>The headers a client adds by itself for one kind of request, from the first request of that kind (HTTP/2 first),
    /// completed with what only HTTP/1.1 requests carried (Connection).</summary>
    private static Dictionary<string, string> Defaults(List<Seen> seen, Dictionary<string, string> spellings, bool webSocket)
    {
        var defaults = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var request in seen.OrderBy(static r => r.Http2 ? 0 : 1).Select(static r => r.Request))
        {
            foreach (var header in request.Headers)
            {
                if (!NotDefaults.Contains(header.Name) && !(webSocket && header.Name.Equals("connection", StringComparison.OrdinalIgnoreCase)))
                {
                    defaults.TryAdd(Spell(header.Name, spellings), header.Value);
                }
            }
        }

        return defaults;
    }

    /// <summary>Headers that depend on how a request was started, not on the protocol: the capture's HTTP/1.1 navigation is made by
    /// script, so it lacks Sec-Fetch-User, which a click sends over either protocol.</summary>
    private static bool IsContextual(string name) => name.StartsWith("sec-fetch-", StringComparison.OrdinalIgnoreCase);

    /// <summary>One order containing every sequence's names, each inserted after its predecessor in the sequence it came from.</summary>
    private static List<string> Merge(IEnumerable<List<string>> sequences)
    {
        var merged = new List<string>();
        foreach (var sequence in sequences)
        {
            var insertAt = 0;
            foreach (var name in sequence)
            {
                var existing = merged.FindIndex(n => n.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (existing >= 0)
                {
                    insertAt = Math.Max(insertAt, existing + 1);
                }
                else
                {
                    merged.Insert(insertAt, name);
                    insertAt++;
                }
            }
        }

        return merged;
    }

    /// <summary>Header name spellings from HTTP/1.1 requests (HTTP/2 lowercases them).</summary>
    private static Dictionary<string, string> Spellings(List<Seen> requests)
    {
        var spellings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in requests.Where(static r => !r.Http2).SelectMany(static r => r.Request.Headers))
        {
            spellings.TryAdd(header.Name, header.Name);
        }

        return spellings;
    }

    private static string Spell(string name, Dictionary<string, string> spellings)
    {
        if (spellings.TryGetValue(name, out var spelled))
        {
            return spelled;
        }

        if (name.StartsWith("sec-ch-", StringComparison.OrdinalIgnoreCase))
        {
            return name.ToLowerInvariant();
        }

        return name.ToLowerInvariant() switch
        {
            "te" => "TE",
            "dnt" => "DNT",
            _ => string.Join('-', name.Split('-').Select(static p => p.Length == 0 ? p : char.ToUpperInvariant(p[0]) + p[1..].ToLowerInvariant())),
        };
    }

    private static ProfileIdentity Identity(UserAgentReport? userAgent, string? productOverride)
    {
        var product = productOverride ?? userAgent?.Product.Replace(" (iOS)", "", StringComparison.Ordinal) ?? "Client";
        var version = userAgent?.MajorVersion?.ToString(CultureInfo.InvariantCulture) ?? "0";
        var platform = userAgent?.Platform switch
        {
            "Windows" => ClientPlatform.Windows,
            "macOS" => ClientPlatform.MacOS,
            "Linux" or "Chrome OS" => ClientPlatform.Linux,
            "Android" => ClientPlatform.Android,
            "iOS" => ClientPlatform.IOS,
            _ => ClientPlatform.Unknown,
        };
        var name = new StringBuilder();
        foreach (var c in $"{product}_{version}_{platform}".ToLowerInvariant())
        {
            name.Append(char.IsAsciiLetterOrDigit(c) ? c : '_');
        }

        return new ProfileIdentity(name.ToString(), platform, product, version);
    }

    /// <summary>"python-requests_2" → "PythonRequests2": a C# identifier from words separated by anything but letters and digits.</summary>
    private static string PascalCase(string words)
    {
        var parts = new StringBuilder();
        var upper = true;
        foreach (var c in words)
        {
            if (!char.IsAsciiLetterOrDigit(c))
            {
                upper = true;
                continue;
            }

            parts.Append(upper ? char.ToUpperInvariant(c) : c);
            upper = false;
        }

        return parts.Length > 0 && char.IsAsciiLetter(parts[0]) ? parts.ToString() : "Client" + parts;
    }

    private static string Summary(int connections, List<Seen> requests)
    {
        var kinds = requests
            .GroupBy(static r => (r.Kind, r.Request.Version))
            .Select(static g => $"{g.Key.Kind} over HTTP/{g.Key.Version} ({g.Count()})");
        return requests.Count == 0
            ? $"Seen: {connections} TLS connection(s), no request."
            : $"Seen: {connections} TLS connection(s); {string.Join(", ", kinds)}.";
    }
}
