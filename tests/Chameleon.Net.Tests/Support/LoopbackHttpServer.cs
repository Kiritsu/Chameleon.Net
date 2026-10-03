using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Chameleon.Net.Tests.Support;

/// <summary>Plain-TCP HTTP/1.1 server: records each raw request (and which connection carried it) and answers with scripted bytes.</summary>
internal sealed class LoopbackHttpServer : IAsyncDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly ConcurrentQueue<ServerRequest> _requests = new();
    private readonly ConcurrentBag<Task> _connections = [];
    private readonly Func<ServerRequest, Reply> _respond;
    private readonly Task _accepting;
    private int _clientClosed;

    public LoopbackHttpServer(Func<ServerRequest, Reply> respond)
    {
        _respond = respond;
        _listener.Start();
        _accepting = AcceptAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public IReadOnlyList<ServerRequest> Requests => [.. _requests];

    /// <summary>Connections the client closed (cleanly, between requests).</summary>
    public int ClientClosedConnections => Volatile.Read(ref _clientClosed);

    public Uri Url(string pathAndQuery) => new($"http://127.0.0.1:{Port}{pathAndQuery}");

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
        for (var index = 0; ; index++)
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

            var connection = index;
            _connections.Add(Task.Run(() => ServeAsync(client, connection)));
        }
    }

    private async Task ServeAsync(TcpClient client, int connection)
    {
        using var _ = client;
        var stream = client.GetStream();
        try
        {
            while (await ReadUntilAsync(stream, "\r\n\r\n") is { } head)
            {
                var request = new ServerRequest(connection, head, await ReadBodyAsync(stream, head));
                _requests.Enqueue(request);

                var reply = _respond(request);
                if (reply.Bytes is null)
                {
                    continue;
                }

                await stream.WriteAsync(reply.Bytes);
                if (reply.Close || request.Header("Connection") is "close")
                {
                    return;
                }
            }

            Interlocked.Increment(ref _clientClosed);
        }
        catch (IOException)
        {
            Interlocked.Increment(ref _clientClosed);
        }
    }

    private static async Task<byte[]> ReadBodyAsync(Stream stream, string head)
    {
        var request = new ServerRequest(0, head, []);
        if (request.Header("Content-Length") is { } length)
        {
            var body = new byte[int.Parse(length, CultureInfo.InvariantCulture)];
            await stream.ReadExactlyAsync(body);
            return body;
        }

        if (request.Header("Transfer-Encoding") is "chunked")
        {
            var body = new List<byte>();
            while (true)
            {
                var size = int.Parse((await ReadUntilAsync(stream, "\r\n"))!, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                var chunk = new byte[size + 2];
                await stream.ReadExactlyAsync(chunk);
                if (size == 0)
                {
                    return [.. body];
                }

                body.AddRange(chunk[..size]);
            }
        }

        return [];
    }

    /// <returns>Null on a clean end of stream before any byte.</returns>
    private static async Task<string?> ReadUntilAsync(Stream stream, string terminator)
    {
        var bytes = new List<byte>();
        var single = new byte[1];
        while (!Encoding.Latin1.GetString([.. bytes]).EndsWith(terminator, StringComparison.Ordinal))
        {
            if (await stream.ReadAsync(single) == 0)
            {
                return bytes.Count == 0 ? null : throw new IOException("Client closed mid-message.");
            }

            bytes.Add(single[0]);
        }

        return Encoding.Latin1.GetString([.. bytes])[..^terminator.Length];
    }
}

internal sealed record ServerRequest(int Connection, string Head, byte[] Body)
{
    public string[] Lines => Head.Split("\r\n");

    public string RequestLine => Lines[0];

    public string Method => RequestLine[..RequestLine.IndexOf(' ', StringComparison.Ordinal)];

    public string Path => RequestLine.Split(' ')[1];

    public IReadOnlyList<string> HeaderNames => [.. Lines[1..].Select(static line => line[..line.IndexOf(':', StringComparison.Ordinal)])];

    public string BodyText => Encoding.UTF8.GetString(Body);

    public string? Header(string name) => Lines[1..]
        .Where(line => line.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase))
        .Select(line => line[(name.Length + 1)..].Trim())
        .FirstOrDefault();
}

/// <param name="Bytes">Null: send nothing and keep waiting.</param>
/// <param name="Close">Close the connection after sending, without announcing it.</param>
internal sealed record Reply(byte[]? Bytes, bool Close = false)
{
    public static Reply None { get; } = new((byte[]?)null);

    public static Reply Raw(string response, bool close = false) => new(Encoding.Latin1.GetBytes(response), close);

    public static Reply Ok(string body, params string[] headers) => Status("200 OK", body, headers);

    public static Reply Status(string status, string body, params string[] headers)
    {
        var bodyBytes = Encoding.UTF8.GetBytes(body);
        var head = $"HTTP/1.1 {status}\r\n{string.Concat(headers.Select(static h => h + "\r\n"))}Content-Length: {bodyBytes.Length}\r\n\r\n";
        return new([.. Encoding.Latin1.GetBytes(head), .. bodyBytes]);
    }
}
