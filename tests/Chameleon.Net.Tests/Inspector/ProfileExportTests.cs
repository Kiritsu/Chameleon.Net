using System.Collections.Concurrent;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Chameleon.Net.Http;
using Chameleon.Net.Inspector.Analysis;
using Chameleon.Net.Inspector.Export;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Profiles;
using Chameleon.Net.Tests.Support;
using Chameleon.Net.WebSockets;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace Chameleon.Net.Tests.Inspector;

/// <summary>Export round trip: a built-in profile walks through the inspector's capture flow, the exported C# is compiled, and the
/// compiled profile walking through the same flow must look identical to the inspector.</summary>
public sealed class ProfileExportTests
{
    private static readonly X509Certificate2 Certificate = TestCertificates.SelfSigned();

    private static readonly Dictionary<string, ClientProfile> Profiles = KnownClients.BuiltIn().ToDictionary(static p => p.Identity.Name);

    private static CancellationToken CancellationToken => TestContext.Current.CancellationToken;

    public static TheoryData<string> ProfileNames => new(Profiles.Keys);

    [Theory]
    [MemberData(nameof(ProfileNames))]
    public async Task ExportedProfileCompilesAndReproducesTheClient(string name)
    {
        var original = Profiles[name];
        var (originalReports, source) = await CaptureAsync(original, export: true);

        var exported = Compile(source!);
        var (exportedReports, _) = await CaptureAsync(exported, export: false);

        Assert.Equal(original.Tls.Shuffle, exported.Tls.Shuffle);
        Assert.Equal(original.Tls.Grease, exported.Tls.Grease);
        // The export states the HPACK rules it saw; a profile without them has the defaults.
        Assert.Equal(original.Http2.Hpack ?? new HpackProfile(), exported.Http2.Hpack);
        Assert.Equal(originalReports.Count, exportedReports.Count);
        foreach (var (expected, actual) in originalReports.Zip(exportedReports))
        {
            var request = $"{expected.Http!.Method} {expected.Http.Path} over HTTP/{expected.Http.Version}";
            Assert.True(Headers(expected).SequenceEqual(Headers(actual)),
                $"{request}:{Environment.NewLine}expected {string.Join(", ", Headers(expected))}{Environment.NewLine}actual   {string.Join(", ", Headers(actual))}");
            Assert.Equal(expected.Tls?.Ja4, actual.Tls?.Ja4);
            Assert.Equal(expected.Http.Ja4H, actual.Http!.Ja4H);
            Assert.Equal(expected.Http.Http2?.Akamai, actual.Http.Http2?.Akamai);
            Assert.Equal(expected.Http.Http2?.Priority, actual.Http.Http2?.Priority);
            Assert.Equal(expected.Http.Http2?.FirstStreamId, actual.Http.Http2?.FirstStreamId);
            if (actual.Tls is not null)
            {
                Assert.Contains(name, actual.Client.TlsMatches);
            }
        }
    }

    /// <summary>What the automated capture proposes: a <c>BuiltInProfiles</c> member, its alias, and the metadata for the pull request.</summary>
    [Fact]
    public async Task BuiltInExportsCompileAsBuiltInProfilesWithTheirAlias()
    {
        var directory = Directory.CreateTempSubdirectory("chameleon-export-");
        try
        {
            await using var server = await InspectorServer.StartAsync([new IPEndPoint(IPAddress.Loopback, 0), new IPEndPoint(IPAddress.IPv6Loopback, 0)], Certificate,
                new ExportSettings(directory.FullName, BuiltIn: true, Client: "Brave", Label: "Brave on a test runner"));
            using var client = Client(BuiltInProfiles.Chromium152Windows, new CookieContainer());
            await SendAsync(client, HttpMethod.Get, $"https://localhost:{server.Port}/", RequestKind.Fetch);
            await SendAsync(client, HttpMethod.Get, $"https://localhost:{server.Port}/profile", RequestKind.Fetch);

            var source = await File.ReadAllTextAsync(Path.Combine(directory.FullName, "Brave152Windows.cs"), CancellationToken);
            var alias = await File.ReadAllTextAsync(Path.Combine(directory.FullName, "Latest", "BraveWindows.cs"), CancellationToken);
            var metadata = await File.ReadAllTextAsync(Path.Combine(directory.FullName, "Brave152Windows.json"), CancellationToken);

            var type = CompileAssembly(source, alias).GetType("Chameleon.Net.Profiles.BuiltInProfiles")!;
            var profile = (ClientProfile)type.GetProperty("Brave152Windows")!.GetValue(null)!;
            Assert.Same(profile, type.GetProperty("BraveWindows")!.GetValue(null));
            Assert.Equal("brave_152_windows", profile.Identity.Name);
            Assert.Contains("/// <summary>Brave on a test runner.", source, StringComparison.Ordinal);
            Assert.Contains("\"alias\": \"BraveWindows\"", metadata, StringComparison.Ordinal);
            Assert.Contains("\"ja4\": \"t13d1516h2_8daaf6152771_806a8c22fdea\"", metadata, StringComparison.Ordinal);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task ProfilesListsClientsAndExportsAnyOfThem()
    {
        await using var server = await StartAsync();
        using var client = Client(BuiltInProfiles.Firefox156Windows, new CookieContainer());
        await client.GetAsync(new Uri($"https://localhost:{server.Port}/hello"), CancellationToken);

        using var other = new HttpClient();
        var list = await other.GetStringAsync(new Uri($"http://localhost:{server.Port}/profiles"), CancellationToken);
        var id = Assert.Single(server.Clients, static c => c.UserAgent?.Contains("Firefox", StringComparison.Ordinal) == true).Id;
        var source = await other.GetStringAsync(new Uri($"http://localhost:{server.Port}/profile/{id}"), CancellationToken);

        Assert.Contains($"\"profile\": \"/profile/{id}\"", list, StringComparison.Ordinal);
        Assert.Contains("public static ClientProfile Firefox156Windows", source, StringComparison.Ordinal);
        Assert.Contains("No WebSocket handshake was seen", source, StringComparison.Ordinal);
        Assert.Equal("firefox_156_windows", Compile(source).Identity.Name);
    }

    [Fact]
    public async Task ExportingAClientWithoutTlsExplainsWhy()
    {
        await using var server = await StartAsync();
        using var client = new HttpClient();

        using var response = await client.GetAsync(new Uri($"http://localhost:{server.Port}/profile"), CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);

        await client.GetAsync(new Uri($"http://localhost:{server.Port}/hello"), CancellationToken);
        using var conflict = await client.GetAsync(new Uri($"http://localhost:{server.Port}/profile"), CancellationToken);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Contains("TLS", await conflict.Content.ReadAsStringAsync(CancellationToken), StringComparison.Ordinal);
    }

    /// <summary>What <c>/capture</c> makes a browser do: navigation, fetch() GET and POST, WebSocket over TLS, then a navigation and a
    /// fetch() over plain HTTP/1.1.</summary>
    private static async Task<(List<InspectionReport> Reports, string? Source)> CaptureAsync(ClientProfile profile, bool export)
    {
        await using var server = await StartAsync();
        var reports = new ConcurrentQueue<InspectionReport>();
        server.Inspected += reports.Enqueue;
        var cookies = new CookieContainer();
        using var client = Client(profile, cookies);
        var https = $"https://localhost:{server.Port}";
        var http = $"http://localhost:{server.Port}";

        await SendAsync(client, HttpMethod.Get, $"{https}/capture", RequestKind.Navigate);
        await SendAsync(client, HttpMethod.Get, $"{https}/capture/fetch", RequestKind.Fetch);
        await SendAsync(client, HttpMethod.Post, $"{https}/capture/post", RequestKind.Fetch, "{\"capture\":true}");
        var connector = new ChameleonWebSocketConnector(Options(profile, cookies));
        using (var socket = await connector.ConnectAsync(new Uri($"wss://localhost:{server.Port}/capture/ws"), profile, cancellationToken: CancellationToken))
        {
            await socket.ReceiveTextAsync(CancellationToken);
        }

        await SendAsync(client, HttpMethod.Get, $"{http}/capture/plain", RequestKind.Navigate);
        await SendAsync(client, HttpMethod.Get, $"{http}/capture/fetch-plain", RequestKind.Fetch);
        var source = export ? await SendAsync(client, HttpMethod.Get, $"{https}/profile", RequestKind.Fetch) : null;
        return ([.. reports], source);
    }

    private static async Task<string> SendAsync(HttpClient client, HttpMethod method, string url, RequestKind kind, string? json = null)
    {
        using var request = new HttpRequestMessage(method, new Uri(url));
        request.Options.Set(ChameleonRequestOptions.Kind, kind);
        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        using var response = await client.SendAsync(request, CancellationToken);
        var body = await response.Content.ReadAsStringAsync(CancellationToken);
        Assert.True(response.IsSuccessStatusCode, body);
        return body;
    }

    private static ClientProfile Compile(string source)
    {
        var property = CompileAssembly(source).GetType("ExportedProfiles")!.GetProperties(BindingFlags.Public | BindingFlags.Static).Single();
        return (ClientProfile)property.GetValue(null)!;
    }

    /// <summary>Compiles like a project with implicit usings, as Chameleon.Net itself is built.</summary>
    private static Assembly CompileAssembly(params string[] sources)
    {
        var references = ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!)
            .Split(Path.PathSeparator)
            .Select(static path => MetadataReference.CreateFromFile(path));
        const string implicitUsings = "global using System; global using System.Collections.Generic; global using System.Linq;";
        var compilation = CSharpCompilation.Create(
            $"Exported{Guid.NewGuid():N}",
            [.. sources.Append(implicitUsings).Select(static s => CSharpSyntaxTree.ParseText(s))],
            references,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));

        using var assembly = new MemoryStream();
        var result = compilation.Emit(assembly);
        Assert.True(result.Success, string.Join(Environment.NewLine,
            result.Diagnostics.Where(static d => d.Severity == DiagnosticSeverity.Error).Select(static d => d.ToString()).Concat(sources)));
        return Assembly.Load(assembly.ToArray());
    }

    /// <summary>Header names and values in order; the WebSocket key is random per handshake, and each run has its own port.</summary>
    private static IEnumerable<string> Headers(InspectionReport report) =>
        report.Http!.Headers.Select(static h => h.Name.ToLowerInvariant() is "sec-websocket-key" or "host" ? h.Name : $"{h.Name}: {h.Value}");

    private static async Task<InspectorServer> StartAsync() =>
        await InspectorServer.StartAsync([new IPEndPoint(IPAddress.Loopback, 0), new IPEndPoint(IPAddress.IPv6Loopback, 0)], Certificate);

    private static ChameleonOptions Options(ClientProfile profile, CookieContainer cookies) => new()
    {
        ProfileSelector = new FixedProfileSelector(profile),
        CertificateValidator = new TrustAnyCertificate(),
        Cookies = cookies,
        TlsSessionResumption = false,
    };

    private static HttpClient Client(ClientProfile profile, CookieContainer cookies) => new(new ChameleonHttpMessageHandler(Options(profile, cookies)));
}
