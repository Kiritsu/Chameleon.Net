using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Chameleon.Net.Transport;

/// <summary>SOCKS5 (RFC 1928) with optional username/password authentication (RFC 1929). Host names are resolved by the proxy.</summary>
public sealed class Socks5Transport : ITransport
{
    private const byte Version = 5;
    private const byte NoAuthentication = 0x00;
    private const byte UsernamePassword = 0x02;
    private const byte NoAcceptableMethods = 0xFF;

    private readonly ITransport _toProxy;
    private readonly DnsEndPoint _proxy;
    private readonly NetworkCredential? _credentials;

    /// <param name="toProxy">How to reach the proxy itself, usually <see cref="TcpTransport"/>.</param>
    public Socks5Transport(ITransport toProxy, DnsEndPoint proxy, NetworkCredential? credentials = null)
    {
        ArgumentNullException.ThrowIfNull(toProxy);
        ArgumentNullException.ThrowIfNull(proxy);

        _toProxy = toProxy;
        _proxy = proxy;
        _credentials = credentials;
    }

    public async Task<Stream> ConnectAsync(DnsEndPoint endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        var request = ConnectRequest(endpoint);

        var stream = await _toProxy.ConnectAsync(_proxy, cancellationToken).ConfigureAwait(false);
        try
        {
            await using (cancellationToken.Register(static state => ((Stream)state!).Dispose(), stream).ConfigureAwait(false))
            {
                await NegotiateAsync(stream, cancellationToken).ConfigureAwait(false);
                await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
                await ReadReplyAsync(stream, endpoint, cancellationToken).ConfigureAwait(false);
            }

            return stream;
        }
        catch (Exception exception)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            if (exception is IOException)
            {
                throw new HttpRequestException(HttpRequestError.ProxyTunnelError, $"The SOCKS5 proxy {_proxy.Host}:{_proxy.Port} closed the connection.", exception);
            }

            throw;
        }
    }

    private async Task NegotiateAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] greeting = _credentials is null ? [Version, 1, NoAuthentication] : [Version, 2, NoAuthentication, UsernamePassword];
        await stream.WriteAsync(greeting, cancellationToken).ConfigureAwait(false);

        var choice = new byte[2];
        await stream.ReadExactlyAsync(choice, cancellationToken).ConfigureAwait(false);
        if (choice[0] != Version)
        {
            throw Failure("is not a SOCKS5 proxy");
        }

        switch (choice[1])
        {
            case NoAuthentication:
                return;
            case UsernamePassword when _credentials is not null:
                var user = Encoding.UTF8.GetBytes(_credentials.UserName);
                var password = Encoding.UTF8.GetBytes(_credentials.Password);
                if (user.Length > 255 || password.Length > 255)
                {
                    throw new ArgumentException("SOCKS5 user names and passwords are limited to 255 bytes.");
                }

                await stream.WriteAsync((byte[])[1, (byte)user.Length, .. user, (byte)password.Length, .. password], cancellationToken).ConfigureAwait(false);
                var status = new byte[2];
                await stream.ReadExactlyAsync(status, cancellationToken).ConfigureAwait(false);
                if (status[1] != 0)
                {
                    throw Failure("rejected the credentials");
                }

                return;
            case NoAcceptableMethods:
                throw Failure(_credentials is null ? "requires authentication" : "accepts none of the offered authentication methods");
            default:
                throw Failure($"selected unsupported authentication method {choice[1]}");
        }
    }

    private static byte[] ConnectRequest(DnsEndPoint endpoint)
    {
        var request = new List<byte> { Version, 1, 0 };
        if (IPAddress.TryParse(endpoint.Host, out var address))
        {
            request.Add(address.AddressFamily == AddressFamily.InterNetworkV6 ? (byte)4 : (byte)1);
            request.AddRange(address.GetAddressBytes());
        }
        else
        {
            var host = Encoding.ASCII.GetBytes(endpoint.Host);
            if (host.Length > 255)
            {
                throw new ArgumentException("SOCKS5 host names are limited to 255 bytes.", nameof(endpoint));
            }

            request.Add(3);
            request.Add((byte)host.Length);
            request.AddRange(host);
        }

        request.Add((byte)(endpoint.Port >> 8));
        request.Add((byte)endpoint.Port);
        return [.. request];
    }

    private async Task ReadReplyAsync(Stream stream, DnsEndPoint endpoint, CancellationToken cancellationToken)
    {
        var reply = new byte[4];
        await stream.ReadExactlyAsync(reply, cancellationToken).ConfigureAwait(false);
        if (reply[0] != Version)
        {
            throw Failure("sent a malformed reply");
        }

        if (reply[1] != 0)
        {
            throw Failure($"refused to connect to {endpoint.Host}:{endpoint.Port}: {ReplyText(reply[1])}");
        }

        var addressLength = reply[3] switch
        {
            1 => 4,
            4 => 16,
            3 => await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false),
            _ => throw Failure("sent an unknown address type"),
        };

        // Bound address and port: not needed for CONNECT.
        await stream.ReadExactlyAsync(new byte[addressLength + 2], cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> ReadByteAsync(Stream stream, CancellationToken cancellationToken)
    {
        var single = new byte[1];
        await stream.ReadExactlyAsync(single, cancellationToken).ConfigureAwait(false);
        return single[0];
    }

    private static string ReplyText(byte code) => code switch
    {
        1 => "general failure",
        2 => "not allowed by ruleset",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => $"error {code}",
    };

    private HttpRequestException Failure(string reason) =>
        new(HttpRequestError.ProxyTunnelError, $"The SOCKS5 proxy {_proxy.Host}:{_proxy.Port} {reason}.");
}
