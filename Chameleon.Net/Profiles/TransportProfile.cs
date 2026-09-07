namespace Chameleon.Net.Profiles;

/// <summary>JA4T inputs. Best effort: managed sockets can only honour <paramref name="Ttl"/>; the rest needs a platform-specific applicator.</summary>
public sealed record TransportProfile(
    int? InitialWindowSize,
    byte? Ttl,
    int? MaximumSegmentSize,
    IReadOnlyList<TcpOptionKind>? OptionOrder);

public enum TcpOptionKind
{
    EndOfOptions = 0,
    NoOperation = 1,
    MaximumSegmentSize = 2,
    WindowScale = 3,
    SackPermitted = 4,
    Sack = 5,
    Timestamps = 8,
}
