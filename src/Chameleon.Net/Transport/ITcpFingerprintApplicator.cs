using System.Net.Sockets;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Transport;

/// <summary>Applies whatever part of a <see cref="TransportProfile"/> the current platform allows before the socket connects.</summary>
public interface ITcpFingerprintApplicator
{
    void Apply(Socket socket, TransportProfile profile);
}
