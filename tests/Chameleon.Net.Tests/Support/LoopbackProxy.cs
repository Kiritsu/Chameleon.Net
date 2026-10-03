using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Chameleon.Net.Tests.Support;

internal enum ProxyKind
{
    HttpConnect,
    Socks5,
}

/// <summary>Minimal HTTP CONNECT or SOCKS5 proxy on loopback: records what the client sent, then relays bytes to the real target.</summary>
internal sealed class LoopbackProxy : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly ConcurrentBag<Task> _connections = [];
    private readonly ProxyKind _kind;
    private readonly NetworkCredential? _required;
    private readonly Task _accepting;

    /// <param name="requiredCredentials">When set, clients must authenticate with exactly these.</param>
    public LoopbackProxy(ProxyKind kind, NetworkCredential? requiredCredentials = null)
    {
        _kind = kind;
        _required = requiredCredentials;
        _listener.Start();
        _accepting = AcceptAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>CONNECT: the raw request head. SOCKS5: "methods=0,2 user=u target=host:port".</summary>
    public ConcurrentQueue<string> Handshakes { get; } = new();

    public Uri Uri(string? userInfo = null) =>
        new($"{(_kind == ProxyKind.Socks5 ? "socks5" : "http")}://{(userInfo is null ? string.Empty : userInfo + "@")}127.0.0.1:{Port}");

    public async ValueTask DisposeAsync()
    {
        _listener.Stop();
        try
        {
            await Task.WhenAll([_accepting, .. _connections]).WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception exception) when (exception is IOException or SocketException or ObjectDisposedException or TimeoutException)
        {
        }
    }

    private async Task AcceptAsync()
    {
        while (true)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync();
            }
            // Stopped while accepting (SocketException, ObjectDisposedException), or between two accepts (InvalidOperationException).
            catch (Exception exception) when (exception is SocketException or ObjectDisposedException or InvalidOperationException)
            {
                return;
            }

            _connections.Add(Task.Run(() => ServeAsync(client)));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using var _ = client;
        var stream = client.GetStream();
        try
        {
            var target = _kind == ProxyKind.HttpConnect ? await ConnectHandshakeAsync(stream) : await Socks5HandshakeAsync(stream);
            if (target is null)
            {
                return;
            }

            using var upstream = target;
            var relay = upstream.GetStream();
            await Task.WhenAny(stream.CopyToAsync(relay), relay.CopyToAsync(stream));
        }
        catch (Exception exception) when (exception is IOException or SocketException or ObjectDisposedException)
        {
        }
    }

    private async Task<TcpClient?> ConnectHandshakeAsync(NetworkStream stream)
    {
        var head = await ReadUntilAsync(stream, "\r\n\r\n");
        Handshakes.Enqueue(head);

        var expected = _required is null
            ? null
            : "Proxy-Authorization: Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_required.UserName}:{_required.Password}"));
        if (expected is not null && !head.Split("\r\n").Contains(expected))
        {
            await stream.WriteAsync("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"test\"\r\nContent-Length: 0\r\n\r\n"u8.ToArray());
            return null;
        }

        var requestLine = head.Split("\r\n")[0].Split(' ');
        if (requestLine[0] != "CONNECT")
        {
            // Forward proxying (absolute-form request): pass the request on in origin form, without the proxy's own header.
            var target = new Uri(requestLine[1]);
            var forwarded = new TcpClient();
            await forwarded.ConnectAsync(target.Host, target.Port);
            var headers = head.Split("\r\n")[1..].Where(static line => !line.StartsWith("Proxy-Authorization:", StringComparison.OrdinalIgnoreCase));
            var rewritten = string.Join("\r\n", [$"{requestLine[0]} {target.PathAndQuery} {requestLine[2]}", .. headers]) + "\r\n\r\n";
            await forwarded.GetStream().WriteAsync(Encoding.Latin1.GetBytes(rewritten));
            return forwarded;
        }

        var authority = requestLine[1];
        var separator = authority.LastIndexOf(':');
        var upstream = new TcpClient();
        await upstream.ConnectAsync(authority[..separator].Trim('[', ']'), int.Parse(authority[(separator + 1)..], System.Globalization.CultureInfo.InvariantCulture));
        await stream.WriteAsync("HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray());
        return upstream;
    }

    private async Task<TcpClient?> Socks5HandshakeAsync(NetworkStream stream)
    {
        var greeting = await ReadAsync(stream, 2);
        var methods = await ReadAsync(stream, greeting[1]);
        var log = new StringBuilder($"methods={string.Join(',', methods)}");

        if (_required is null)
        {
            await stream.WriteAsync(new byte[] { 5, 0 });
        }
        else if (!methods.Contains((byte)2))
        {
            await stream.WriteAsync(new byte[] { 5, 0xFF });
            Handshakes.Enqueue(log.ToString());
            return null;
        }
        else
        {
            await stream.WriteAsync(new byte[] { 5, 2 });
            var version = await ReadAsync(stream, 2);
            var user = Encoding.UTF8.GetString(await ReadAsync(stream, version[1]));
            var password = Encoding.UTF8.GetString(await ReadAsync(stream, (await ReadAsync(stream, 1))[0]));
            log.Append(" user=").Append(user);
            var ok = user == _required.UserName && password == _required.Password;
            await stream.WriteAsync(new byte[] { 1, ok ? (byte)0 : (byte)1 });
            if (!ok)
            {
                Handshakes.Enqueue(log.ToString());
                return null;
            }
        }

        var request = await ReadAsync(stream, 4);
        string host = request[3] switch
        {
            1 => new IPAddress(await ReadAsync(stream, 4)).ToString(),
            4 => new IPAddress(await ReadAsync(stream, 16)).ToString(),
            _ => Encoding.ASCII.GetString(await ReadAsync(stream, (await ReadAsync(stream, 1))[0])),
        };
        var portBytes = await ReadAsync(stream, 2);
        var port = (portBytes[0] << 8) | portBytes[1];
        Handshakes.Enqueue(log.Append(System.Globalization.CultureInfo.InvariantCulture, $" type={request[3]} target={host}:{port}").ToString());

        var upstream = new TcpClient();
        await upstream.ConnectAsync(host, port);
        await stream.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
        return upstream;
    }

    private static async Task<byte[]> ReadAsync(Stream stream, int count)
    {
        var buffer = new byte[count];
        await stream.ReadExactlyAsync(buffer);
        return buffer;
    }

    private static async Task<string> ReadUntilAsync(Stream stream, string terminator)
    {
        var bytes = new List<byte>();
        var single = new byte[1];
        while (!Encoding.Latin1.GetString([.. bytes]).EndsWith(terminator, StringComparison.Ordinal))
        {
            if (await stream.ReadAsync(single) == 0)
            {
                throw new IOException("Client closed mid-handshake.");
            }

            bytes.Add(single[0]);
        }

        return Encoding.Latin1.GetString([.. bytes])[..^terminator.Length];
    }
}

/// <summary>Sends every request through one proxy; unlike <see cref="WebProxy"/> it never bypasses loopback.</summary>
internal sealed class FixedProxy(Uri proxy) : IWebProxy
{
    public ICredentials? Credentials { get; set; }

    public Uri GetProxy(Uri destination) => proxy;

    public bool IsBypassed(Uri host) => false;
}
