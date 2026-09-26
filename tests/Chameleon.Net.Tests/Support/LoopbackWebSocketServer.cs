using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using Chameleon.Net.WebSockets;

namespace Chameleon.Net.Tests.Support;

/// <summary>Single-connection plain-TCP WebSocket server: records the raw request head, answers the upgrade, then echoes messages.</summary>
internal sealed class LoopbackWebSocketServer : IAsyncDisposable
{
    private const string AcceptGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly TaskCompletionSource<string> _requestHead = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task _serving;

    /// <param name="acceptedExtensions">Sent as <c>Sec-WebSocket-Extensions</c> in the 101, and used by the server side too.</param>
    /// <param name="sentWithUpgrade">Bytes written in the same write as the 101 response.</param>
    /// <param name="respond">Replaces the whole response (raw text); the connection closes after it.</param>
    public LoopbackWebSocketServer(string? acceptedExtensions = null, byte[]? sentWithUpgrade = null, Func<string, string>? respond = null)
    {
        _listener.Start();
        _serving = ServeAsync(acceptedExtensions, sentWithUpgrade ?? [], respond);
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public Uri Uri => new($"ws://127.0.0.1:{Port}/chat?room=1");

    /// <summary>The request line and headers, without the terminating empty line.</summary>
    public Task<string> RequestHead => _requestHead.Task;

    public async ValueTask DisposeAsync()
    {
        _listener.Stop();
        try
        {
            await _serving.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (Exception exception) when (exception is IOException or SocketException or WebSocketException or ObjectDisposedException or TimeoutException)
        {
        }
    }

    private async Task ServeAsync(string? acceptedExtensions, byte[] sentWithUpgrade, Func<string, string>? respond)
    {
        using var client = await _listener.AcceptTcpClientAsync();
        var stream = client.GetStream();
        var head = await ReadHeadAsync(stream);
        _requestHead.SetResult(head);

        if (respond is not null)
        {
            await stream.WriteAsync(Encoding.Latin1.GetBytes(respond(head)));
            return;
        }

        var key = head.Split("\r\n").Single(line => line.StartsWith("Sec-WebSocket-Key:", StringComparison.OrdinalIgnoreCase))[18..].Trim();
#pragma warning disable CA5350 // Mandated by RFC 6455.
        var accept = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + AcceptGuid)));
#pragma warning restore CA5350
        var response = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            + $"Sec-WebSocket-Accept: {accept}\r\n"
            + (acceptedExtensions is null ? string.Empty : $"Sec-WebSocket-Extensions: {acceptedExtensions}\r\n")
            + "\r\n";
        await stream.WriteAsync((byte[])[.. Encoding.Latin1.GetBytes(response), .. sentWithUpgrade]);

        using var webSocket = WebSocket.CreateFromStream(stream, new WebSocketCreationOptions
        {
            IsServer = true,
            DangerousDeflateOptions = acceptedExtensions is null ? null : PerMessageDeflate.Negotiate([acceptedExtensions], offered: true),
        });

        var buffer = new byte[1 << 20];
        while (true)
        {
            var length = 0;
            ValueWebSocketReceiveResult result;
            do
            {
                result = await webSocket.ReceiveAsync(buffer.AsMemory(length), CancellationToken.None);
                length += result.Count;
            }
            while (!result.EndOfMessage);

            if (result.MessageType == WebSocketMessageType.Close)
            {
                await webSocket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                return;
            }

            await webSocket.SendAsync(buffer.AsMemory(0, length), result.MessageType, true, CancellationToken.None);
        }
    }

    private static async Task<string> ReadHeadAsync(Stream stream)
    {
        var head = new List<byte>();
        var single = new byte[1];
        while (head.Count < 4 || head[^4] != '\r' || head[^3] != '\n' || head[^2] != '\r' || head[^1] != '\n')
        {
            if (await stream.ReadAsync(single) == 0)
            {
                throw new IOException("Client closed before sending a full request head.");
            }

            head.Add(single[0]);
        }

        return Encoding.Latin1.GetString([.. head.SkipLast(4)]);
    }
}
