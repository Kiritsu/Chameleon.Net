using System.Net;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Http;

public interface IHttpConnectionFactory
{
    ValueTask<IHttpConnection> OpenAsync(Origin origin, ClientProfile profile, IWebProxy? proxy, CancellationToken cancellationToken);
}
