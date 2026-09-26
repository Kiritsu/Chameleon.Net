using System.Collections.Concurrent;
using System.Diagnostics;
using Chameleon.Net.Profiles;
using Org.BouncyCastle.Tls.Crypto;

namespace Chameleon.Net.Tls;

/// <summary>A TLS 1.3 NewSessionTicket plus the resumption PSK derived from it (RFC 8446 §4.6.1).</summary>
internal sealed record SessionTicket(byte[] Identity, byte[] Psk, int PrfAlgorithm, int CryptoHashAlgorithm, uint AgeAdd, long ReceivedAt, TimeSpan Lifetime)
{
    /// <summary>RFC 8446 caps ticket lifetimes at 7 days.</summary>
    public static readonly TimeSpan MaxLifetime = TimeSpan.FromDays(7);

    public bool IsExpired => Stopwatch.GetElapsedTime(ReceivedAt) >= Lifetime;

    /// <summary>Ticket age in milliseconds plus the server's age_add, modulo 2^32.</summary>
    public uint ObfuscatedAge => unchecked((uint)(long)Stopwatch.GetElapsedTime(ReceivedAt).TotalMilliseconds + AgeAdd);

    public int HashLength => TlsCryptoUtilities.GetHashOutputSize(CryptoHashAlgorithm);
}

/// <summary>TLS 1.3 session tickets, per host and port. Everything given the same instance resumes each other's sessions: pass one
/// through <see cref="ChameleonOptions.TlsSessionCache"/> to a <see cref="Http.ChameleonHttpMessageHandler"/> and a
/// <see cref="WebSockets.ChameleonWebSocketConnector"/> to behave like a single OkHttpClient (one Conscrypt session cache) serving
/// both REST calls and WebSockets.</summary>
/// <remarks>Each ticket is used once, as BoringSSL (Chrome, Conscrypt) does. Tickets are also kept apart per ClientHello shape
/// (cipher suites and extension order; ALPN contents don't count), so a ticket never links connections made under different profiles.</remarks>
public sealed class TlsSessionCache
{
    private const int MaxTicketsPerHost = 8;

    private readonly ConcurrentDictionary<string, ConcurrentQueue<SessionTicket>> _tickets = new();

    internal void Add(string host, int port, TlsProfile profile, SessionTicket ticket)
    {
        var queue = _tickets.GetOrAdd(Key(host, port, profile), static _ => new ConcurrentQueue<SessionTicket>());
        queue.Enqueue(ticket);
        while (queue.Count > MaxTicketsPerHost && queue.TryDequeue(out _))
        {
        }
    }

    internal SessionTicket? Take(string host, int port, TlsProfile profile)
    {
        if (!_tickets.TryGetValue(Key(host, port, profile), out var queue))
        {
            return null;
        }

        while (queue.TryDequeue(out var ticket))
        {
            if (!ticket.IsExpired)
            {
                return ticket;
            }
        }

        return null;
    }

    // Not the TlsProfile record itself: its lists compare by reference, so a profile rebuilt per connection (WithAlpn) would never match.
    private static string Key(string host, int port, TlsProfile profile) =>
        $"{host}:{port}|{string.Join(',', profile.CipherSuites)}|{string.Join(',', profile.Extensions.Select(static extension => extension.Type))}";
}
