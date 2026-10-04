using System.Net;
using System.Text.RegularExpressions;
using Chameleon.Net.Http.Http2.Hpack;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Analysis;

/// <summary>Cross-layer checks of the kind bot management runs cheaply on every request: does the TLS stack, the HTTP/2 preface and the headers
/// belong to the client the User-Agent names? Reference values come from the built-in profiles, which were captured from the real clients.</summary>
internal sealed partial class ConsistencyChecker(
    KnownClients known,
    ConnectionCapture connection,
    RequestCapture request,
    ClientReport client,
    IReadOnlyList<KnownClient> tlsMatches,
    IReadOnlyList<KnownClient> http2Matches)
{
    private static readonly string[] ConnectionSpecificHeaders = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host"];

    private readonly List<Finding> _findings = [];
    private readonly UserAgentReport? _userAgent = client.UserAgent;

    public List<Finding> Run()
    {
        var reference = Reference();
        CheckUserAgent();
        if (connection.Hello is not null)
        {
            CheckTls(reference);
        }

        if (request.Version == "2" && connection.Http2 is not null)
        {
            CheckHttp2(reference);
        }

        if (reference is not null)
        {
            CheckHeaders(reference);
        }

        CheckClientHints();
        return [.. _findings.OrderByDescending(static f => f.Severity)];
    }

    private bool ClaimsBrowser => _userAgent?.Family is ClientFamily.Chromium or ClientFamily.Firefox or ClientFamily.Safari;

    private bool ClaimsKnownStack => ClaimsBrowser || _userAgent?.Family == ClientFamily.OkHttp;

    /// <summary>The built-in profile to compare headers and HTTP/2 details with, among those of the claimed family: the one sending this
    /// exact User-Agent first, then this sec-ch-ua (Brave's User-Agent is Chrome's, its brands aren't), then one the TLS matched, then
    /// one named like the User-Agent's product (Edge's for an Edge User-Agent).</summary>
    private KnownClient? Reference()
    {
        if (_userAgent is null)
        {
            return null;
        }

        var brands = request.Header("sec-ch-ua");
        return known.Clients
            .Where(c => c.Family == _userAgent.Family)
            .Select((client, index) => (Client: client, Index: index, Score:
                (Sends(client, "user-agent", _userAgent.Raw) ? 8 : 0)
                + (brands is not null && Sends(client, "sec-ch-ua", brands) ? 4 : 0)
                + (tlsMatches.Contains(client) ? 2 : 0)
                + (client.Profile.Identity.ClientFamily.Equals(_userAgent.Product, StringComparison.OrdinalIgnoreCase) ? 1 : 0)))
            .OrderByDescending(static c => c.Score)
            .ThenBy(static c => c.Index)
            .Select(static c => c.Client)
            .FirstOrDefault();

        static bool Sends(KnownClient client, string name, string value) =>
            Enum.GetValues<RequestKind>().Any(kind => client.Profile.Headers.DefaultsFor(kind, http2: true)
                .Any(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase) && h.Value == value));
    }

    private void CheckUserAgent()
    {
        if (_userAgent is null)
        {
            Add(Severity.High, "http", "user-agent-missing", "No User-Agent. Browsers and mobile HTTP clients always send one; requests without it are commonly challenged or blocked.");
        }
        else if (_userAgent.Family == ClientFamily.Tool)
        {
            Add(Severity.Info, "http", "user-agent-tool", $"The User-Agent declares {_userAgent.Product}: bot management treats declared tools as automated.");
        }
        else if (_userAgent.Family == ClientFamily.Unknown)
        {
            Add(Severity.Info, "http", "user-agent-unknown", $"Unrecognised User-Agent product '{_userAgent.Product}': only cross-layer checks that don't depend on it ran.");
        }
    }

    private void CheckTls(KnownClient? reference)
    {
        var hello = connection.Hello!;
        var order = connection.ExtensionOrder;

        if (ClaimsKnownStack && client.TlsFamily != _userAgent!.Family)
        {
            Add(Severity.High, "tls", "tls-family", client.TlsFamily == ClientFamily.Unknown
                ? $"The User-Agent claims {_userAgent.Product}, but the ClientHello {client.TlsFamilyReason}."
                : $"The User-Agent claims {_userAgent.Product} ({_userAgent.Family}), but the ClientHello is {client.TlsFamily}'s: {client.TlsFamilyReason}.");
        }
        else if (ClaimsKnownStack && tlsMatches.Count == 0 && reference is not null)
        {
            Add(Severity.Low, "tls", "tls-unknown-version", $"Same TLS stack as {reference.Name}, but not the same ClientHello: another version or configuration.");
        }

        if (_userAgent?.Family == ClientFamily.Chromium && client.TlsFamily == ClientFamily.Chromium)
        {
            if (order is { Connections: >= 2, DistinctOrders: 1 })
            {
                Add(Severity.Medium, "tls", "extension-order-fixed",
                    $"Chrome shuffles its TLS extensions on every connection, but {order.Connections} connections with this ClientHello used one order.");
            }

            if (_userAgent.MajorVersion >= 131 && !hello.KeyShares.Any(static k => k.Group == 0x11EC))
            {
                Add(Severity.Medium, "tls", "post-quantum-missing", "Chrome 131 and later send an X25519MLKEM768 key share.");
            }
        }
        else if (order is { DistinctOrders: > 1 } && client.TlsFamily != ClientFamily.Chromium)
        {
            Add(Severity.Medium, "tls", "extension-order-shuffled",
                $"{order.DistinctOrders} extension orders over {order.Connections} connections with this ClientHello: only Chrome shuffles, and this isn't Chrome's.");
        }

        if (ClaimsBrowser && !request.WebSocket && !hello.Alpn.Contains("h2"))
        {
            Add(Severity.High, "tls", "alpn-without-h2", "Browsers offer h2 in ALPN on every HTTPS connection except for WebSockets.");
        }

        var host = Host();
        if (host is not null && !IPAddress.TryParse(host.Trim('[', ']'), out _))
        {
            if (hello.ServerName is null)
            {
                Add(Severity.Medium, "tls", "sni-missing", $"No server_name for {host}: clients send SNI for every host name.");
            }
            else if (!hello.ServerName.Equals(host, StringComparison.OrdinalIgnoreCase))
            {
                Add(Severity.Medium, "tls", "sni-mismatch", $"SNI '{hello.ServerName}' differs from the requested host '{host}'.");
            }
        }
    }

    private void CheckHttp2(KnownClient? reference)
    {
        var http2 = connection.Http2!;
        if (_userAgent is not null && known.Clients.Any(c => c.Family == _userAgent.Family) && client.Http2Family != _userAgent.Family)
        {
            Add(Severity.High, "http2", "http2-family",
                $"The User-Agent claims {_userAgent.Product}, but the HTTP/2 preface is {(client.Http2Family == ClientFamily.Unknown ? "no known client's" : $"{client.Http2Family}'s")}: " +
                $"{http2.Akamai}, where {reference?.Name ?? _userAgent.Product} sends {reference?.Akamai ?? "something else"}.");
        }
        else if (reference is not null && !http2Matches.Any(m => m.Family == reference.Family))
        {
            Add(Severity.Low, "http2", "http2-unknown-version", $"HTTP/2 preface {http2.Akamai} is {reference.Family}-like but differs from {reference.Name}'s {reference.Akamai}.");
        }

        if (reference is null || client.Http2Family != reference.Family)
        {
            return;
        }

        var profile = reference.Profile.Http2;
        var expected = Enum.GetValues<RequestKind>().Where(static k => k != RequestKind.WebSocket)
            .Select(profile.PriorityFor).Distinct()
            .Select(static p => p is { } priority ? new PriorityReport((int)priority.DependencyStreamId, priority.Weight + 1, priority.Exclusive) : null)
            .ToList();
        if (!expected.Contains(request.Priority))
        {
            Add(Severity.Low, "http2", "headers-priority",
                $"HEADERS priority {Describe(request.Priority)} isn't one {reference.Name} uses ({string.Join(" or ", expected.Select(Describe))}).");
        }

        if (http2.FirstStreamId != profile.FirstStreamId)
        {
            Add(Severity.Low, "http2", "first-stream-id", $"The first request used stream {http2.FirstStreamId}; {reference.Name} starts at {profile.FirstStreamId}.");
        }

        if (request.StreamId == http2.FirstStreamId && request.Hpack is { } hpack)
        {
            CheckHpack(reference, hpack);
        }

        var cookies = request.Headers.Where(static h => h.Name.Equals("cookie", StringComparison.OrdinalIgnoreCase)).ToList();
        var splits = profile.Hpack?.SplitCookies == true;
        if (splits && cookies is [{ } joined] && joined.Value.Contains(';', StringComparison.Ordinal))
        {
            Add(Severity.Medium, "http2", "cookies-joined", $"Several cookies in one cookie field; {reference.Name} sends each cookie as its own field.");
        }
        else if (!splits && cookies.Count > 1)
        {
            Add(Severity.Medium, "http2", "cookies-split", $"{cookies.Count} cookie fields; {reference.Name} sends its cookies joined in one field.");
        }

        static string Describe(PriorityReport? priority) =>
            priority is null ? "none" : $"{(priority.Exclusive ? "exclusive " : "")}weight {priority.Weight} on stream {priority.DependsOn}";
    }

    /// <summary>On a connection's first request both dynamic tables start empty, so the reference client's encoder, given the same fields,
    /// must produce the same representations: indexed or literal, which literal, Huffman or raw.</summary>
    private void CheckHpack(KnownClient reference, IReadOnlyList<HpackFieldReport> hpack)
    {
        var observed = hpack.Where(static f => f.Representation != HpackRepresentation.SizeUpdate).ToList();
        var regular = request.Headers.GetEnumerator();
        var fields = new List<KeyValuePair<string, string>>(observed.Count);
        foreach (var field in observed)
        {
            var value = field.Name switch
            {
                ":method" => request.Method,
                ":path" => request.Path,
                ":authority" => request.Authority,
                ":scheme" => connection.Hello is null ? "http" : "https",
                _ => regular.MoveNext() ? regular.Current.Value : null,
            };
            if (value is null)
            {
                return;
            }

            fields.Add(new(field.Name!, value));
        }

        var trace = new List<HpackFieldTrace>();
        new HpackDecoder(int.MaxValue).Decode(new HpackEncoder().Encode(fields), trace);
        var expected = trace
            .Where(static t => t.Representation != HpackRepresentation.SizeUpdate)
            .Select(static t => Describe(t.Representation, t.Index, t.ValueHuffman, t.NameHuffman))
            .ToList();

        var differences = observed
            .Select(static f => (f.Name, Actual: Describe(f.Representation, f.Index ?? 0, f.Huffman, f.NameHuffman)))
            .Zip(expected, static (field, wanted) => (field.Name, field.Actual, Expected: wanted))
            .Where(static f => f.Actual != f.Expected)
            .ToList();
        if (differences.Count > 0)
        {
            var first = differences[0];
            Add(Severity.Medium, "http2", "hpack-representation",
                $"{differences.Count} header field(s) encoded unlike {reference.Name}'s HPACK encoder; first '{first.Name}': {first.Actual}, expected {first.Expected}.");
        }

        static string Describe(HpackRepresentation representation, int index, bool valueHuffman, bool nameHuffman) =>
            representation == HpackRepresentation.Indexed
                ? $"indexed {index}"
                : $"{representation} literal with {(index == 0 ? $"a new {(nameHuffman ? "Huffman" : "raw")} name" : $"name {index}")} and a {(valueHuffman ? "Huffman" : "raw")} value";
    }

    private void CheckHeaders(KnownClient reference)
    {
        var profile = reference.Profile;
        var http2 = request.Version == "2";
        var kinds = request.WebSocket ? [RequestKind.WebSocket] : Enum.GetValues<RequestKind>().Where(static k => k != RequestKind.WebSocket).ToArray();
        var orders = request.WebSocket
            ? [profile.WebSocket.HandshakeHeaderOrder]
            : kinds.Select(profile.Headers.OrderFor).Distinct().ToList();

        if (profile.Headers.OrderMode == HeaderOrderMode.ProfileOrder)
        {
            var inversions = orders.Select(FirstInversion).ToList();
            if (inversions.All(static i => i is not null))
            {
                var (first, second) = inversions[0]!.Value;
                Add(Severity.Medium, "http", "header-order", $"Header order differs from {reference.Name}: '{first}' came before '{second}'.");
            }
        }

        if (!http2)
        {
            var spellings = orders.SelectMany(static o => o).Distinct(StringComparer.Ordinal).ToList();
            var miscased = request.Headers
                .Select(h => (Received: h.Name, Expected: ExpectedSpelling(h.Name, spellings, profile.Headers.Http1Casing)))
                .Where(static h => h.Expected is not null && !string.Equals(h.Received, h.Expected, StringComparison.Ordinal))
                .ToList();
            if (miscased.Count > 0)
            {
                Add(Severity.Medium, "http", "header-casing",
                    $"Header name casing differs from {reference.Name}: {string.Join(", ", miscased.Select(static m => $"'{m.Received}' (expected '{m.Expected}')"))}.");
            }
        }

        var required = kinds
            .Select(k => profile.Headers.DefaultsFor(k, http2).Select(static h => h.Key.ToLowerInvariant()).ToHashSet())
            .Aggregate(static (a, b) => { a.IntersectWith(b); return a; });
        if (http2)
        {
            required.ExceptWith(ConnectionSpecificHeaders);
        }

        var missing = required.Where(name => request.Header(name) is null).Order(StringComparer.Ordinal).ToList();
        if (missing.Count > 0)
        {
            Add(Severity.Medium, "http", "missing-headers", $"{reference.Name} always sends {string.Join(", ", missing)}; missing here.");
        }

        var acceptEncodings = kinds.Select(k => profile.Headers.DefaultsFor(k, http2)
            .FirstOrDefault(static h => h.Key.Equals("accept-encoding", StringComparison.OrdinalIgnoreCase)).Value).Distinct().ToList();
        var acceptEncoding = request.Header("accept-encoding");
        if (acceptEncodings is [{ } expectedEncoding] && acceptEncoding is not null && acceptEncoding != expectedEncoding)
        {
            Add(Severity.Low, "http", "accept-encoding", $"Accept-Encoding '{acceptEncoding}'; {reference.Name} sends '{expectedEncoding}'.");
        }
    }

    private void CheckClientHints()
    {
        var brands = request.Header("sec-ch-ua");
        if (_userAgent?.Family is ClientFamily.Firefox or ClientFamily.Safari)
        {
            if (brands is not null)
            {
                Add(Severity.High, "http", "client-hints-unexpected", $"{_userAgent.Product} doesn't implement client hints, but sec-ch-ua was sent.");
            }

            return;
        }

        if (_userAgent?.Family != ClientFamily.Chromium || request.WebSocket)
        {
            return;
        }

        if (brands is null)
        {
            if (connection.Hello is not null)
            {
                Add(Severity.Low, "http", "client-hints-missing", "Chrome sends sec-ch-ua, sec-ch-ua-mobile and sec-ch-ua-platform on HTTPS requests.");
            }

            return;
        }

        var list = BrandPattern().Matches(brands).Select(static m => (Brand: m.Groups[1].Value, Version: m.Groups[2].Value)).ToList();
        var major = _userAgent.MajorVersion?.ToString(System.Globalization.CultureInfo.InvariantCulture);
        if (major is not null && !list.Any(b => b.Version == major))
        {
            Add(Severity.High, "http", "client-hints-version", $"sec-ch-ua ({brands}) has no brand at version {major}, the User-Agent's.");
        }

        var edgeBrand = list.Any(static b => b.Brand == "Microsoft Edge");
        if (_userAgent.Product == "Edge" && !edgeBrand)
        {
            Add(Severity.High, "http", "client-hints-brand", "Edge User-Agent, but sec-ch-ua has no \"Microsoft Edge\" brand.");
        }
        else if (_userAgent.Product != "Edge" && edgeBrand)
        {
            Add(Severity.High, "http", "client-hints-brand", $"sec-ch-ua names Microsoft Edge, but the User-Agent is {_userAgent.Product}'s.");
        }

        var platform = request.Header("sec-ch-ua-platform")?.Trim('"');
        if (platform is not null && _userAgent.Platform is not null && platform != _userAgent.Platform)
        {
            Add(Severity.High, "http", "client-hints-platform", $"sec-ch-ua-platform is {platform}, the User-Agent says {_userAgent.Platform}.");
        }

        var mobile = request.Header("sec-ch-ua-mobile");
        if (mobile is not null && mobile != (_userAgent.Mobile ? "?1" : "?0"))
        {
            Add(Severity.Medium, "http", "client-hints-mobile", $"sec-ch-ua-mobile is {mobile}, but the User-Agent is {(_userAgent.Mobile ? "" : "not ")}mobile.");
        }
    }

    /// <summary>The first pair of received headers in the opposite order to <paramref name="order"/>, among the headers it lists.</summary>
    private (string, string)? FirstInversion(IReadOnlyList<string> order)
    {
        var positions = request.Headers
            .Select(h => (h.Name, Position: IndexOf(order, h.Name)))
            .Where(static h => h.Position >= 0)
            .ToList();
        for (var i = 1; i < positions.Count; i++)
        {
            if (positions[i].Position < positions[i - 1].Position)
            {
                return (positions[i - 1].Name, positions[i].Name);
            }
        }

        return null;
    }

    private static string? ExpectedSpelling(string name, IReadOnlyList<string> spellings, HeaderCasing casing)
    {
        var listed = spellings.FirstOrDefault(s => s.Equals(name, StringComparison.OrdinalIgnoreCase));
        return listed is null ? null : casing switch
        {
            HeaderCasing.LowerCase => listed.ToLowerInvariant(),
            HeaderCasing.TitleCase => string.Join('-', listed.Split('-').Select(static p => p.Length == 0 ? p : char.ToUpperInvariant(p[0]) + p[1..].ToLowerInvariant())),
            _ => listed,
        };
    }

    private static int IndexOf(IReadOnlyList<string> order, string name)
    {
        for (var i = 0; i < order.Count; i++)
        {
            if (order[i].Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return i;
            }
        }

        return -1;
    }

    private string? Host()
    {
        var authority = request.Authority ?? request.Header("host");
        if (string.IsNullOrEmpty(authority))
        {
            return null;
        }

        return authority.StartsWith('[') ? authority[..(authority.IndexOf(']', StringComparison.Ordinal) + 1)]
            : authority.Contains(':', StringComparison.Ordinal) ? authority[..authority.LastIndexOf(':')]
            : authority;
    }

    private void Add(Severity severity, string layer, string id, string message) => _findings.Add(new Finding(severity, layer, id, message));

    [GeneratedRegex("\"([^\"]*)\";\\s*v=\"([^\"]*)\"")]
    private static partial Regex BrandPattern();
}
