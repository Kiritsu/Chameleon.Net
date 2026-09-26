using Chameleon.Net.Http;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Tests;

public sealed class ProfileSelectorTests
{
    private static readonly Origin Origin = new("https", "example.com", 443);
    private static readonly ClientProfile A = Named("a");
    private static readonly ClientProfile B = Named("b");
    private static readonly ClientProfile C = Named("c");

    [Fact]
    public void RoundRobinCycles()
    {
        var selector = new RoundRobinProfileSelector([A, B, C]);

        Assert.Equal([A, B, C, A, B], Enumerable.Range(0, 5).Select(_ => selector.SelectForConnection(Origin)));
    }

    [Fact]
    public void RandomSelectionFollowsWeights()
    {
        var selector = new RandomProfileSelector([new WeightedProfile(A, 8), new WeightedProfile(B, 2)]);

        var picks = Enumerable.Range(0, 20_000).Select(_ => selector.SelectForConnection(Origin)).ToList();
        var shareOfA = picks.Count(p => p == A) / (double)picks.Count;

        Assert.InRange(shareOfA, 0.77, 0.83);
        Assert.DoesNotContain(C, picks);
    }

    [Fact]
    public void UnweightedRandomReachesEveryProfile()
    {
        var selector = new RandomProfileSelector([A, B, C]);

        Assert.Equal(3, Enumerable.Range(0, 1_000).Select(_ => selector.SelectForConnection(Origin)).Distinct().Count());
    }

    [Fact]
    public void InvalidInputIsRejected()
    {
        Assert.Throws<ArgumentException>(() => new RoundRobinProfileSelector([]));
        Assert.Throws<ArgumentException>(() => new RandomProfileSelector([new WeightedProfile(A, 0)]));
        Assert.Throws<ArgumentException>(() => new RandomProfileSelector([new WeightedProfile(A, double.NaN)]));
    }

    private static ClientProfile Named(string name) =>
        BuiltInProfiles.OkHttp4Android13 with { Identity = BuiltInProfiles.OkHttp4Android13.Identity with { Name = name } };
}
