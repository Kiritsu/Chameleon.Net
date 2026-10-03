using System.Globalization;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using Chameleon.Net.Inspector.Reports;

namespace Chameleon.Net.Inspector.Server;

/// <summary>HTTP/1.x with header names kept exactly as sent, and WebSocket upgrades: the report goes out as the first text message.</summary>
internal sealed class Http1Session(Stream stream, Func<RequestCapture, InspectorResponse> respond)
{
    private const int MaxHeadLength = 64 * 1024;

    private readonly byte[] _buffer = new byte[MaxHeadLength];
    private int _start;
    private int _end;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (await ReadHeadAsync(cancellationToken) is { } head)
        {
            var lines = head.Split("\r\n");
            var requestLine = lines[0].Split(' ');
            if (requestLine.Length != 3 || !requestLine[2].StartsWith("HTTP/", StringComparison.Ordinal))
            {
                throw new InvalidDataException($"Not an HTTP/1.x request line: {lines[0]}");
            }

            var headers = lines.Skip(1)
                .Where(static l => l.Contains(':', StringComparison.Ordinal))
                .Select(static l => new HeaderField(l[..l.IndexOf(':', StringComparison.Ordinal)], l[(l.IndexOf(':', StringComparison.Ordinal) + 1)..].Trim()))
                .ToList();
            string? Header(string name) => headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value;

            var version = requestLine[2]["HTTP/".Length..];
            var webSocket = Header("upgrade")?.Contains("websocket", StringComparison.OrdinalIgnoreCase) == true && Header("sec-websocket-key") is not null;
            var request = new RequestCapture(version, requestLine[0], requestLine[1], Header("host"), headers, [], webSocket);

            if (webSocket)
            {
                await UpgradeAsync(request, Header("sec-websocket-key")!, cancellationToken);
                return;
            }

            await SkipBodyAsync(Header("content-length"), Header("transfer-encoding"), cancellationToken);
            var response = respond(request);
            var close = Header("connection")?.Contains("close", StringComparison.OrdinalIgnoreCase) == true
                || (version == "1.0" && Header("connection")?.Contains("keep-alive", StringComparison.OrdinalIgnoreCase) != true);
            var responseHead = new StringBuilder()
                .Append(CultureInfo.InvariantCulture, $"HTTP/1.1 {response.Status} {(response.Status == 200 ? "OK" : "Not Found")}\r\n")
                .Append(CultureInfo.InvariantCulture, $"Content-Type: {response.ContentType}\r\n")
                .Append(CultureInfo.InvariantCulture, $"Content-Length: {response.Body.Length}\r\n")
                .Append("Cache-Control: no-store\r\n")
                .Append("Access-Control-Allow-Origin: *\r\n")
                .Append(string.Concat((response.Headers ?? []).Select(static h => $"{h.Key}: {h.Value}\r\n")))
                .Append(close ? "Connection: close\r\n" : "")
                .Append("\r\n")
                .ToString();
            await stream.WriteAsync(Encoding.ASCII.GetBytes(responseHead), cancellationToken);
            if (request.Method != "HEAD")
            {
                await stream.WriteAsync(response.Body, cancellationToken);
            }

            await stream.FlushAsync(cancellationToken);
            if (close)
            {
                return;
            }
        }
    }

    private async Task UpgradeAsync(RequestCapture request, string key, CancellationToken cancellationToken)
    {
#pragma warning disable CA5350 // SHA-1 is what RFC 6455 specifies for Sec-WebSocket-Accept.
        var accept = Convert.ToBase64String(SHA1.HashData(Encoding.ASCII.GetBytes(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));
#pragma warning restore CA5350
        await stream.WriteAsync(Encoding.ASCII.GetBytes(
            $"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"), cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var leftover = _buffer.AsMemory(_start, _end - _start).ToArray();
        using var socket = WebSocket.CreateFromStream(new ReplayStream(leftover, stream), new WebSocketCreationOptions { IsServer = true, KeepAliveInterval = TimeSpan.Zero });
        await socket.SendAsync(respond(request).Body, WebSocketMessageType.Text, endOfMessage: true, cancellationToken);
        await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "inspected", cancellationToken);

        // Wait briefly for the client's close frame so it sees a clean close.
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        var buffer = new byte[4096];
        try
        {
            while (socket.State == WebSocketState.CloseSent)
            {
                await socket.ReceiveAsync(buffer, timeout.Token);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }
        catch (WebSocketException)
        {
            // The client dropped the connection instead of answering the close: it has its report already.
        }
    }

    private async Task<string?> ReadHeadAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var end = _buffer.AsSpan(_start, _end - _start).IndexOf("\r\n\r\n"u8);
            if (end >= 0)
            {
                var head = Encoding.Latin1.GetString(_buffer, _start, end);
                _start += end + 4;
                return head;
            }

            if (_end - _start == _buffer.Length)
            {
                throw new InvalidDataException("Request head exceeds 64 KiB.");
            }

            if (await FillAsync(cancellationToken) == 0)
            {
                return null;
            }
        }
    }

    private async Task SkipBodyAsync(string? contentLength, string? transferEncoding, CancellationToken cancellationToken)
    {
        if (transferEncoding?.Contains("chunked", StringComparison.OrdinalIgnoreCase) == true)
        {
            while (true)
            {
                var sizeLine = await ReadLineAsync(cancellationToken);
                var size = long.Parse(sizeLine.Split(';')[0].Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                if (size == 0)
                {
                    while ((await ReadLineAsync(cancellationToken)).Length > 0)
                    {
                        // Trailers.
                    }

                    return;
                }

                await SkipAsync(size + 2, cancellationToken);
            }
        }

        if (long.TryParse(contentLength, NumberStyles.None, CultureInfo.InvariantCulture, out var length))
        {
            await SkipAsync(length, cancellationToken);
        }
    }

    private async Task<string> ReadLineAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            var end = _buffer.AsSpan(_start, _end - _start).IndexOf("\r\n"u8);
            if (end >= 0)
            {
                var line = Encoding.Latin1.GetString(_buffer, _start, end);
                _start += end + 2;
                return line;
            }

            if (_end - _start == _buffer.Length || await FillAsync(cancellationToken) == 0)
            {
                throw new InvalidDataException("Malformed chunked body.");
            }
        }
    }

    private async Task SkipAsync(long count, CancellationToken cancellationToken)
    {
        while (count > 0)
        {
            if (_start == _end && await FillAsync(cancellationToken) == 0)
            {
                throw new EndOfStreamException("The connection closed inside a request body.");
            }

            var take = (int)Math.Min(count, _end - _start);
            _start += take;
            count -= take;
        }
    }

    private async Task<int> FillAsync(CancellationToken cancellationToken)
    {
        if (_start > 0)
        {
            _buffer.AsSpan(_start, _end - _start).CopyTo(_buffer);
            _end -= _start;
            _start = 0;
        }

        var read = await stream.ReadAsync(_buffer.AsMemory(_end), cancellationToken);
        _end += read;
        return read;
    }
}
