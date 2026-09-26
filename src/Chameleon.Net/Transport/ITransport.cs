using System.Net;

namespace Chameleon.Net.Transport;

/// <summary>Opens the raw byte stream the TLS layer runs over: direct TCP, an HTTP CONNECT tunnel, or SOCKS5.</summary>
public interface ITransport
{
    Task<Stream> ConnectAsync(DnsEndPoint endpoint, CancellationToken cancellationToken = default);
}
