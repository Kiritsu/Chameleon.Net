using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Chameleon.Net.Inspector;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Server;

const string usage = """
    Chameleon.Net Inspector: shows what a CDN can see of a client (JA3/JA4, Akamai HTTP/2, JA4H, header order) and where it contradicts its User-Agent.

    Usage: Chameleon.Net.Inspector [--port 8443] [--listen loopback|any|<address>] [--cert <file.pfx> [--cert-password <password>]] [--log <file.jsonl>]

      --port      TLS and plain HTTP on the same port (default 8443). HTTP/2 over TLS via ALPN, or h2c with prior knowledge.
      --listen    loopback (default), any (to test a phone on the same network), or one address.
      --cert      PFX to serve instead of a fresh self-signed certificate.
      --log       Append every report to this file as one JSON line.

    Every request is answered with its JSON report; a WebSocket upgrade gets it as the first text message.

    Profile export: open https://localhost:<port>/capture in a browser to export it as a Chameleon.Net profile (C#).
    /profiles lists every client seen and /profile/<id> exports one of them, such as an app on a phone.
    """;

var port = 8443;
var listen = "loopback";
string? certificatePath = null;
string? certificatePassword = null;
string? logPath = null;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--port" when i + 1 < args.Length && int.TryParse(args[i + 1], out port):
            i++;
            break;
        case "--listen" when i + 1 < args.Length:
            listen = args[++i];
            break;
        case "--cert" when i + 1 < args.Length:
            certificatePath = args[++i];
            break;
        case "--cert-password" when i + 1 < args.Length:
            certificatePassword = args[++i];
            break;
        case "--log" when i + 1 < args.Length:
            logPath = args[++i];
            break;
        default:
            Console.WriteLine(usage);
            return args[i] is "-h" or "--help" ? 0 : 1;
    }
}

IPEndPoint[] endpoints = listen switch
{
    "loopback" => [new IPEndPoint(IPAddress.Loopback, port), new IPEndPoint(IPAddress.IPv6Loopback, port)],
    "any" => [new IPEndPoint(IPAddress.IPv6Any, port)],
    _ when IPAddress.TryParse(listen, out var address) => [new IPEndPoint(address, port)],
    _ => throw new ArgumentException($"--listen: '{listen}' is not loopback, any or an IP address."),
};

using var certificate = certificatePath is null ? InspectorCertificate.CreateSelfSigned() : InspectorCertificate.Load(certificatePath, certificatePassword);
await using var server = await InspectorServer.StartAsync(endpoints, certificate);

var compact = new JsonSerializerOptions(ReportJson.Options) { WriteIndented = false };
var output = new Lock();
server.Inspected += report =>
{
    lock (output)
    {
        ReportPrinter.Print(report, Console.Out);
        if (logPath is not null)
        {
            File.AppendAllText(logPath, JsonSerializer.Serialize(report, compact) + Environment.NewLine);
        }
    }
};
server.ConnectionFailed += exception =>
{
    lock (output)
    {
        Console.WriteLine($"! {exception.GetType().Name}: {exception.Message}");
    }
};

Console.WriteLine($"Listening on {string.Join(", ", server.EndPoints)} (TLS and plain HTTP).");
Console.WriteLine($"  https://localhost:{server.Port}/   http://localhost:{server.Port}/   wss://localhost:{server.Port}/");
Console.WriteLine($"Certificate SHA-256: {Convert.ToHexString(SHA256.HashData(certificate.RawData))} (self-signed unless --cert)");
Console.WriteLine($"Export a browser's profile: https://localhost:{server.Port}/capture   Any client's: http://localhost:{server.Port}/profiles");
Console.WriteLine("Ctrl+C to stop.");

var stopped = new TaskCompletionSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    stopped.TrySetResult();
};
await stopped.Task;
return 0;
