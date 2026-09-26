using System.Net;
using System.Text;
using Chameleon.Net.Http;
using Chameleon.Net.Http.Http1;

namespace Chameleon.Net.Transport;

/// <summary>Tunnels through an HTTP proxy with <c>CONNECT</c>, shaped like OkHttp's tunnel request
/// (<c>Host</c>, <c>Proxy-Connection: Keep-Alive</c>, <c>User-Agent</c>). Credentials are sent preemptively as Basic.</summary>
public sealed class HttpConnectTransport : ITransport
{
    private readonly ITransport _toProxy;
    private readonly DnsEndPoint _proxy;
    private readonly NetworkCredential? _credentials;
    private readonly string? _userAgent;

    /// <param name="toProxy">How to reach the proxy itself, usually <see cref="TcpTransport"/>.</param>
    public HttpConnectTransport(ITransport toProxy, DnsEndPoint proxy, NetworkCredential? credentials = null, string? userAgent = null)
    {
        ArgumentNullException.ThrowIfNull(toProxy);
        ArgumentNullException.ThrowIfNull(proxy);

        _toProxy = toProxy;
        _proxy = proxy;
        _credentials = credentials;
        _userAgent = userAgent;
    }

    public async Task<Stream> ConnectAsync(DnsEndPoint endpoint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        var authority = endpoint.Host.Contains(':', StringComparison.Ordinal) ? $"[{endpoint.Host}]:{endpoint.Port}" : $"{endpoint.Host}:{endpoint.Port}";
        var headers = new List<KeyValuePair<string, string>>
        {
            new("Host", authority),
            new("Proxy-Connection", "Keep-Alive"),
        };
        if (_userAgent is not null)
        {
            headers.Add(new("User-Agent", _userAgent));
        }

        if (_credentials is not null)
        {
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_credentials.UserName}:{_credentials.Password}"));
            headers.Add(new("Proxy-Authorization", $"Basic {token}"));
        }

        var request = Http1RequestHead.Encode("CONNECT", authority, headers);
        var stream = new HttpReadStream(await _toProxy.ConnectAsync(_proxy, cancellationToken).ConfigureAwait(false));
        try
        {
            Http1ResponseHead response;
            // A blocking inner stream ignores the token; closing it is what unblocks the read.
            await using (cancellationToken.Register(static state => ((Stream)state!).Dispose(), stream).ConfigureAwait(false))
            {
                await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                response = await stream.ReadResponseHeadAsync(cancellationToken).ConfigureAwait(false);
            }

            if (response.StatusCode is < 200 or > 299)
            {
                throw new HttpRequestException(HttpRequestError.ProxyTunnelError,
                    $"The proxy {_proxy.Host}:{_proxy.Port} refused the tunnel to {authority} with HTTP {response.StatusCode}.",
                    null, (HttpStatusCode)response.StatusCode);
            }

            // Anything the proxy sent after its head belongs to the tunnel; HttpReadStream serves it first.
            return stream;
        }
        catch (IOException exception)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw new HttpRequestException(HttpRequestError.ProxyTunnelError, $"The proxy {_proxy.Host}:{_proxy.Port} did not answer the CONNECT request.", exception);
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }
}
