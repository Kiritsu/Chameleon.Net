using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Chameleon.Net.Fingerprints;
using Chameleon.Net.Http.Http2.Hpack;
using Chameleon.Net.Inspector.Analysis;
using Chameleon.Net.Inspector.Export;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Tls;

namespace Chameleon.Net.Inspector.Server;

/// <summary>Accepts TLS and plain connections on the same port, records the ClientHello before handing the connection to SslStream,
/// and answers every request with its <see cref="InspectionReport"/> as JSON (as a text message for WebSockets).</summary>
internal sealed class InspectorServer : IAsyncDisposable
{
    /// <summary>Largest /capture/bytes body: past every browser's initial connection window (Chrome's is 15 MB) twice over.</summary>
    private const int MaxCaptureBytes = 64 << 20;

    private static ReadOnlySpan<byte> Http2Preface => "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8;

    private readonly List<Socket> _listeners;
    private readonly SslServerAuthenticationOptions _tlsOptions;
    private readonly ReportBuilder _reports;
    private readonly ExtensionOrderTracker _orders = new();
    private readonly ClientRegistry _clients = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Task> _tasks = [];
    private readonly Lock _tasksLock = new();
    private int _connectionIds;

    private readonly ExportSettings _export;

    private InspectorServer(List<Socket> listeners, X509Certificate2 certificate, KnownClients known, ExportSettings export)
    {
        _listeners = listeners;
        _export = export;
        _reports = new ReportBuilder(known);
        _tlsOptions = new SslServerAuthenticationOptions
        {
            ServerCertificateContext = SslStreamCertificateContext.Create(certificate, additionalCertificates: null),
            ApplicationProtocols = [SslApplicationProtocol.Http2, SslApplicationProtocol.Http11],
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
        };
    }

    /// <summary>Raised for every request, and for TLS handshakes that failed before one (TLS fingerprint only).</summary>
    public event Action<InspectionReport>? Inspected;

    /// <summary>Raised when a connection fails for a reason other than the client going away.</summary>
    public event Action<Exception>? ConnectionFailed;

    /// <summary>An HTTP/2 connection ended.</summary>
    public event Action<ConnectionLogReport>? ConnectionClosed;

    public IReadOnlyList<IPEndPoint> EndPoints => [.. _listeners.Select(static l => (IPEndPoint)l.LocalEndPoint!)];

    public int Port => EndPoints[0].Port;

    /// <param name="endpoints">Port 0 picks a free port, shared by every endpoint. <see cref="IPAddress.IPv6Any"/> also accepts IPv4.</param>
    /// <param name="export">How <c>/profile</c> exports are written, and where they are also saved. Defaults: standalone C#, not saved.</param>
    public static async Task<InspectorServer> StartAsync(IEnumerable<IPEndPoint> endpoints, X509Certificate2 certificate, ExportSettings? export = null)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var known = await KnownClients.CreateAsync();
        var listeners = new List<Socket>();
        try
        {
            var port = 0;
            foreach (var endpoint in endpoints)
            {
                var listener = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                if (endpoint.Address.Equals(IPAddress.IPv6Any))
                {
                    listener.DualMode = true;
                }

                try
                {
                    listener.Bind(new IPEndPoint(endpoint.Address, endpoint.Port == 0 ? port : endpoint.Port));
                }
                catch (SocketException exception) when (listeners.Count > 0 && endpoint.Address.Equals(IPAddress.IPv6Loopback)
                    && exception.SocketErrorCode is SocketError.AddressNotAvailable or SocketError.AddressFamilyNotSupported)
                {
                    // No IPv6 loopback (some containers): IPv4 alone will do.
                    listener.Dispose();
                    continue;
                }
                catch
                {
                    listener.Dispose();
                    throw;
                }

                listeners.Add(listener);
                listener.Listen(512);
                port = ((IPEndPoint)listener.LocalEndPoint!).Port;
            }
        }
        catch
        {
            listeners.ForEach(static l => l.Dispose());
            throw;
        }

        var server = new InspectorServer(listeners, certificate, known, export ?? new ExportSettings());
        foreach (var listener in listeners)
        {
            server.Track(server.AcceptLoopAsync(listener));
        }

        return server;
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _listeners.ForEach(static l => l.Dispose());
        Task[] tasks;
        lock (_tasksLock)
        {
            tasks = [.. _tasks];
        }

        await Task.WhenAll(tasks).ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
        _stop.Dispose();
    }

    private async Task AcceptLoopAsync(Socket listener)
    {
        while (!_stop.IsCancellationRequested)
        {
            Socket socket;
            try
            {
                socket = await listener.AcceptAsync(_stop.Token);
            }
            catch (Exception exception) when (exception is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            Track(HandleAsync(socket));
        }
    }

    private void Track(Task task)
    {
        lock (_tasksLock)
        {
            _tasks.RemoveAll(static t => t.IsCompleted);
            _tasks.Add(task);
        }
    }

    private async Task HandleAsync(Socket socket)
    {
        await Task.Yield();
        socket.NoDelay = true;
        var connection = new ConnectionCapture(Interlocked.Increment(ref _connectionIds), (IPEndPoint)socket.RemoteEndPoint!);
        var stream = new NetworkStream(socket, ownsSocket: true);
        var cancellationToken = _stop.Token;
        try
        {
            var first = new byte[1];
            if (await stream.ReadAsync(first, cancellationToken) == 0)
            {
                return;
            }

            if (first[0] == 22)
            {
                await HandleTlsAsync(connection, stream, first[0], cancellationToken);
            }
            else
            {
                await HandlePlainAsync(connection, stream, first[0], cancellationToken);
            }
        }
        catch (Exception exception) when (exception is IOException or SocketException or EndOfStreamException || cancellationToken.IsCancellationRequested)
        {
            // The client went away, or the server is stopping.
        }
        catch (Exception exception) when (exception is InvalidDataException or FormatException or HpackException or WebSocketException)
        {
            ConnectionFailed?.Invoke(exception);
        }
        finally
        {
            await stream.DisposeAsync();
            if (connection.Http2 is { } http2)
            {
                ConnectionClosed?.Invoke(new ConnectionLogReport(connection.Id, connection.Remote.ToString(), connection.Alpn, http2.Akamai, connection.Http2Events()));
            }
        }
    }

    private async Task HandleTlsAsync(ConnectionCapture connection, Stream network, byte first, CancellationToken cancellationToken)
    {
        var (records, handshake, recordVersion) = await ClientHelloReader.ReadAsync(network, first, cancellationToken);
        connection.Hello = ClientHelloDetails.Parse(handshake);
        connection.RecordVersion = recordVersion;
        connection.HelloLength = handshake.Length;
        byte[] record = [22, (byte)(recordVersion >> 8), (byte)recordVersion, (byte)(handshake.Length >> 8), (byte)handshake.Length, .. handshake];
        connection.Fingerprint = TlsFingerprinter.Compute(ClientHelloParser.Parse(record));
        connection.ExtensionOrder = _orders.Record(connection.Remote.Address, KnownClients.TlsKey(connection.Hello), connection.Hello);

        await using var tls = new SslStream(new ReplayStream(records, network), leaveInnerStreamOpen: false);
        try
        {
            await tls.AuthenticateAsServerAsync(_tlsOptions, cancellationToken);
        }
        catch (Exception exception) when (exception is AuthenticationException or IOException)
        {
            // Typically the client rejecting the self-signed certificate: the ClientHello is still worth reporting.
            var failed = _reports.Build(connection, request: null, $"TLS handshake failed: {exception.InnerException?.Message ?? exception.Message}");
            _clients.Record(connection, request: null, failed);
            Inspected?.Invoke(failed);
            return;
        }

        connection.TlsVersion = tls.SslProtocol.ToString();
        connection.CipherSuite = tls.NegotiatedCipherSuite.ToString();
        connection.Alpn = tls.NegotiatedApplicationProtocol.Protocol.IsEmpty ? null : tls.NegotiatedApplicationProtocol.ToString();

        if (connection.Alpn == "h2")
        {
            await new Http2Session(tls, connection, Responder(connection)).RunAsync(prefaceRead: false, cancellationToken);
        }
        else
        {
            await new Http1Session(tls, Responder(connection)).RunAsync(cancellationToken);
        }
    }

    /// <summary>HTTP/1.x, or HTTP/2 with prior knowledge (h2c) when the connection starts with the HTTP/2 preface.</summary>
    private async Task HandlePlainAsync(ConnectionCapture connection, Stream network, byte first, CancellationToken cancellationToken)
    {
        var prefix = new byte[Http2Preface.Length];
        prefix[0] = first;
        var length = 1;
        while (length < prefix.Length && prefix.AsSpan(0, length).SequenceEqual(Http2Preface[..length]))
        {
            var read = await network.ReadAsync(prefix.AsMemory(length), cancellationToken);
            if (read == 0)
            {
                return;
            }

            length += read;
        }

        if (length == prefix.Length && prefix.AsSpan().SequenceEqual(Http2Preface))
        {
            await new Http2Session(network, connection, Responder(connection)).RunAsync(prefaceRead: true, cancellationToken);
        }
        else
        {
            await new Http1Session(new ReplayStream(prefix.AsMemory(0, length), network), Responder(connection)).RunAsync(cancellationToken);
        }
    }

    /// <summary>The clients seen so far, each with what's needed to export its profile.</summary>
    public IReadOnlyList<ClientSnapshot> Clients => _clients.Snapshot();

    /// <summary>Routes: <c>/profiles</c> lists clients, <c>/profile</c> exports the caller's profile and <c>/profile/{id}</c> another
    /// client's, <c>/capture</c> walks a browser through the requests an export needs. Everything else answers with its report.</summary>
    private Func<RequestCapture, InspectorResponse> Responder(ConnectionCapture connection) => request =>
    {
        var path = request.Path.Split('?')[0];
        if (path == "/favicon.ico")
        {
            return new InspectorResponse(404, "text/plain", []);
        }

        if (path == "/profiles")
        {
            var clients = _clients.Snapshot().Select(static c => new
            {
                c.Id,
                Address = c.Address.ToString(),
                c.UserAgent,
                Connections = c.Observations.Select(static o => o.Connection).Distinct().Count(),
                Requests = c.Observations.Count(static o => o.Request is not null),
                Profile = $"/profile/{c.Id}",
            });
            return new InspectorResponse(200, "application/json; charset=utf-8", JsonSerializer.SerializeToUtf8Bytes(clients, ReportJson.Options));
        }

        if (path == "/profile" || path.StartsWith("/profile/", StringComparison.Ordinal))
        {
            var client = path == "/profile"
                ? _clients.Find(connection.Remote.Address, request.Header("user-agent"))
                : int.TryParse(path["/profile/".Length..], out var id) ? _clients.Find(id) : null;
            return client is null
                ? Text(404, "No such client yet. /profiles lists the clients seen.")
                : Export(client);
        }

        var report = _reports.Build(connection, request);
        _clients.Record(connection, request, report);
        Inspected?.Invoke(report);

        if (!request.WebSocket && path == "/capture")
        {
            return new InspectorResponse(200, "text/html; charset=utf-8", System.Text.Encoding.UTF8.GetBytes(CapturePages.Start),
                // Two cookies: browsers that split the Cookie header into one HTTP/2 field per cookie show it only with more than one.
                [new("Set-Cookie", $"{CapturePages.CookieName}=1; Path=/"), new("Set-Cookie", $"{CapturePages.CookieName}_second=2; Path=/")]);
        }

        if (!request.WebSocket && path == "/capture/plain")
        {
            return new InspectorResponse(200, "text/html; charset=utf-8", System.Text.Encoding.UTF8.GetBytes(CapturePages.Plain));
        }

        // A body large enough to make the client acknowledge it: its WINDOW_UPDATEs show its flow control.
        if (!request.WebSocket && path.StartsWith("/capture/bytes/", StringComparison.Ordinal)
            && int.TryParse(path["/capture/bytes/".Length..], CultureInfo.InvariantCulture, out var size) && size is >= 0 and <= MaxCaptureBytes)
        {
            return new InspectorResponse(200, "application/octet-stream", new byte[size]);
        }

        return new InspectorResponse(200, "application/json; charset=utf-8", JsonSerializer.SerializeToUtf8Bytes(report, ReportJson.Options));
    };

    private InspectorResponse Export(ClientSnapshot client)
    {
        ExportedProfile export;
        try
        {
            export = ProfileExporter.Export(client, _export.Client);
        }
        catch (InvalidOperationException exception)
        {
            return Text(409, exception.Message);
        }

        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var source = _export.BuiltIn
            ? ProfileSourceWriter.WriteBuiltIn(export, _export.Label ?? $"{export.Profile.Identity.ClientFamily} {export.Profile.Identity.Version} on {export.Profile.Identity.Platform}", today)
            : ProfileSourceWriter.Write(export,
            [
                $"Exported by the Chameleon.Net Inspector on {today:yyyy-MM-dd} from {client.Address}.",
                $"User-Agent: {client.UserAgent ?? "(none)"}",
            ]);

        if (_export.Directory is { } directory)
        {
            SaveExport(directory, client, export, source);
        }

        return Text(200, source);
    }

    /// <summary>Writes <c>{Property}.cs</c>, <c>Latest/{Alias}.cs</c> and <c>{Property}.json</c> (what a reviewer needs: fingerprints,
    /// verdict, findings, notes). The JSON is written last: its presence means the export is complete.</summary>
    private void SaveExport(string directory, ClientSnapshot client, ExportedProfile export, string source)
    {
        Directory.CreateDirectory(Path.Combine(directory, "Latest"));
        File.WriteAllText(Path.Combine(directory, $"{export.PropertyName}.cs"), source);
        if (_export.BuiltIn)
        {
            File.WriteAllText(Path.Combine(directory, "Latest", $"{export.AliasName}.cs"), ProfileSourceWriter.WriteAlias(export));
        }

        var reports = client.Observations.Select(static o => o.Report).ToList();
        var metadata = new ExportMetadata(
            export.Profile.Identity.Name,
            export.PropertyName,
            export.AliasName,
            _export.Label,
            client.UserAgent,
            export.Fingerprints.Ja4,
            export.Fingerprints.Ja3Hash,
            export.Profile.Tls.Shuffle != Profiles.ExtensionShufflePolicy.None,
            export.Fingerprints.Akamai,
            reports.Count == 0 ? Verdict.Consistent : reports.Max(static r => r.Verdict),
            [.. reports.SelectMany(static r => r.Findings).DistinctBy(static f => f.Id)],
            export.Notes);
        File.WriteAllText(Path.Combine(directory, $"{export.PropertyName}.json"), JsonSerializer.Serialize(metadata, ReportJson.Options));
    }

    private static InspectorResponse Text(int status, string text) => new(status, "text/plain; charset=utf-8", System.Text.Encoding.UTF8.GetBytes(text));
}

/// <param name="Directory">Where every export is also saved, for automation (eng/profile-capture).</param>
/// <param name="BuiltIn">Write exports as members of Chameleon.Net's <c>BuiltInProfiles</c>, with a "latest" alias.</param>
/// <param name="Client">Product name to use instead of the User-Agent's (Brave sends Chrome's).</param>
/// <param name="Label">Provenance for the built-in profile's documentation, e.g. "Google Chrome 153.0.7012.4 on GitHub Actions windows-2025".</param>
internal sealed record ExportSettings(string? Directory = null, bool BuiltIn = false, string? Client = null, string? Label = null);

/// <summary>Saved next to each export, for the pull request that proposes it.</summary>
internal sealed record ExportMetadata(
    string Name,
    string Property,
    string Alias,
    string? Label,
    string? UserAgent,
    string Ja4,
    string Ja3Hash,
    bool ExtensionShuffle,
    string? Akamai,
    Verdict Verdict,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<string> Notes);
