using System.Globalization;
using System.Net;
using Chameleon.Net.Inspector.Reports;
using Chameleon.Net.Inspector.Tls;

namespace Chameleon.Net.Inspector.Server;

/// <summary>Remembers the extension orders each address used per ClientHello (<see cref="Analysis.KnownClients.TlsKey"/>: SNI, ALPN and PSK aside,
/// so a client's WebSocket connections count too), which is how a server tells Chrome's per-connection shuffle from a fixed order.</summary>
internal sealed class ExtensionOrderTracker
{
    private const int MaxEntries = 10_000;

    private readonly Dictionary<(IPAddress Address, string Hello), Entry> _seen = [];
    private readonly Lock _lock = new();

    public ExtensionOrderReport Record(IPAddress address, string helloKey, ClientHelloDetails hello)
    {
        var order = string.Join(',', hello.ExtensionTypes.Select(static t => TlsNames.IsGrease(t) ? "GREASE" : t.ToString(CultureInfo.InvariantCulture)));
        lock (_lock)
        {
            if (_seen.Count >= MaxEntries)
            {
                _seen.Clear();
            }

            address = ClientRegistry.Normalize(address);
            if (!_seen.TryGetValue((address, helloKey), out var entry))
            {
                _seen[(address, helloKey)] = entry = new Entry();
            }

            entry.Connections++;
            entry.Orders.Add(order);
            return new ExtensionOrderReport(entry.Connections, entry.Orders.Count);
        }
    }

    private sealed class Entry
    {
        public int Connections { get; set; }
        public HashSet<string> Orders { get; } = [];
    }
}
