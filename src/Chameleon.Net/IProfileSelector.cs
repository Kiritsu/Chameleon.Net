using Chameleon.Net.Http;
using Chameleon.Net.Profiles;

namespace Chameleon.Net;

/// <summary>Fingerprints are per connection, so selection happens when a connection is opened, never per request.</summary>
public interface IProfileSelector
{
    ClientProfile SelectForConnection(Origin origin);
}
