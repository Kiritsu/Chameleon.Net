using System.Net;

namespace Chameleon.Net.Inspector.Server;

/// <summary>Groups what was seen by client (address and User-Agent), so a profile can be exported from all of one client's
/// connections and requests: a navigation, a fetch(), a WebSocket, over HTTP/2 and HTTP/1.1.</summary>
internal sealed class ClientRegistry
{
    private const int MaxClients = 200;
    private const int MaxObservations = 200;

    private readonly List<ObservedClient> _clients = [];
    private readonly Lock _lock = new();
    private int _nextId;

    /// <param name="request">Null for a connection that ended before a request (only its ClientHello is known).</param>
    public void Record(ConnectionCapture connection, RequestCapture? request)
    {
        var address = Normalize(connection.Remote.Address);
        var userAgent = request?.Header("user-agent");
        lock (_lock)
        {
            var client = _clients.FirstOrDefault(c => c.Address.Equals(address) && c.UserAgent == userAgent);
            if (client is null)
            {
                if (_clients.Count >= MaxClients)
                {
                    _clients.RemoveAt(0);
                }

                client = new ObservedClient(++_nextId, address, userAgent);
                _clients.Add(client);
            }

            if (client.Observations.Count >= MaxObservations)
            {
                client.Observations.RemoveAt(0);
            }

            client.Observations.Add(new Observation(connection, request));
        }
    }

    public IReadOnlyList<ClientSnapshot> Snapshot()
    {
        lock (_lock)
        {
            return [.. _clients.Select(static c => new ClientSnapshot(c.Id, c.Address, c.UserAgent, [.. c.Observations]))];
        }
    }

    public ClientSnapshot? Find(int id) => Snapshot().FirstOrDefault(c => c.Id == id);

    public ClientSnapshot? Find(IPAddress address, string? userAgent) =>
        Snapshot().LastOrDefault(c => c.Address.Equals(Normalize(address)) && c.UserAgent == userAgent);

    /// <summary>One client whether it reached the server over IPv4 or IPv6: a browser may resolve localhost differently per connection.</summary>
    public static IPAddress Normalize(IPAddress address) =>
        IPAddress.IsLoopback(address) ? IPAddress.Loopback
        : address.IsIPv4MappedToIPv6 ? address.MapToIPv4()
        : address;

    private sealed class ObservedClient(int id, IPAddress address, string? userAgent)
    {
        public int Id { get; } = id;
        public IPAddress Address { get; } = address;
        public string? UserAgent { get; } = userAgent;
        public List<Observation> Observations { get; } = [];
    }
}

internal sealed record Observation(ConnectionCapture Connection, RequestCapture? Request);

internal sealed record ClientSnapshot(int Id, IPAddress Address, string? UserAgent, IReadOnlyList<Observation> Observations);
