using Chameleon.Net.Http;
using Chameleon.Net.Profiles;

namespace Chameleon.Net;

/// <summary>Cycles through the profiles, one per new connection. Pooled connections keep the profile they were opened with:
/// with HTTP/2 an origin shares one connection, so rotation shows up across origins or after the connection closes.</summary>
public sealed class RoundRobinProfileSelector : IProfileSelector
{
    private readonly ClientProfile[] _profiles;
    private int _next = -1;

    public RoundRobinProfileSelector(IEnumerable<ClientProfile> profiles)
    {
        ArgumentNullException.ThrowIfNull(profiles);
        _profiles = [.. profiles];
        if (_profiles.Length == 0 || Array.Exists(_profiles, static profile => profile is null))
        {
            throw new ArgumentException("At least one profile is required, and none may be null.", nameof(profiles));
        }
    }

    public ClientProfile SelectForConnection(Origin origin) =>
        _profiles[(int)((uint)Interlocked.Increment(ref _next) % (uint)_profiles.Length)];
}

public readonly record struct WeightedProfile(ClientProfile Profile, double Weight);

/// <summary>Picks a profile at random for each new connection, optionally weighted (e.g. by real-world market share).
/// Same pooling caveat as <see cref="RoundRobinProfileSelector"/>.</summary>
public sealed class RandomProfileSelector : IProfileSelector
{
    private readonly ClientProfile[] _profiles;
    private readonly double[] _cumulativeWeights;

    public RandomProfileSelector(IEnumerable<ClientProfile> profiles)
        : this(profiles?.Select(static profile => new WeightedProfile(profile, 1)) ?? throw new ArgumentNullException(nameof(profiles)))
    {
    }

    /// <param name="weightedProfiles">Relative weights; they don't need to sum to 1.</param>
    public RandomProfileSelector(IEnumerable<WeightedProfile> weightedProfiles)
    {
        ArgumentNullException.ThrowIfNull(weightedProfiles);
        var entries = weightedProfiles.ToArray();
        if (entries.Length == 0 || Array.Exists(entries, static entry => entry.Profile is null || !(entry.Weight > 0) || double.IsInfinity(entry.Weight)))
        {
            throw new ArgumentException("At least one profile is required, each with a finite positive weight.", nameof(weightedProfiles));
        }

        _profiles = [.. entries.Select(static entry => entry.Profile)];
        _cumulativeWeights = new double[entries.Length];
        var total = 0d;
        for (var i = 0; i < entries.Length; i++)
        {
            total += entries[i].Weight;
            _cumulativeWeights[i] = total;
        }
    }

    public ClientProfile SelectForConnection(Origin origin)
    {
        var roll = Random.Shared.NextDouble() * _cumulativeWeights[^1];
        var index = Array.BinarySearch(_cumulativeWeights, roll);
        return _profiles[Math.Min(index < 0 ? ~index : index + 1, _profiles.Length - 1)];
    }
}
