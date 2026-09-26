using Chameleon.Net.Profiles;
using Chameleon.Net.Transport;

namespace Chameleon.Net.Tls;

/// <summary>Performs the profiled handshake over a transport stream. The seam that replaces SslStream.</summary>
public interface ITlsConnectionFactory
{
    Task<TlsConnection> ConnectAsync(ITransport transport, string host, int port, TlsProfile profile, CancellationToken cancellationToken = default);
}

/// <param name="SessionResumed">The server accepted a session ticket from an earlier connection (TLS 1.3 PSK resumption).</param>
public sealed record TlsConnection(Stream Stream, string? NegotiatedProtocol, bool SessionResumed = false);
