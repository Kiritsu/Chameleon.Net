using System.Globalization;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Fingerprints;

/// <summary>Akamai HTTP/2 fingerprint (Shuster &amp; Glazer, Black Hat EU 2017): <c>SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order</c>,
/// e.g. <c>1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p</c>. Priority weights are shown as 1–256, i.e. wire value + 1.</summary>
public static class AkamaiFingerprint
{
    public static string Compute(Http2Profile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        var settings = profile.Preface.OfType<Http2SettingsFrame>().FirstOrDefault()?.Settings ?? [];
        var windowUpdate = profile.Preface.OfType<Http2WindowUpdateFrame>().FirstOrDefault();
        var priorities = profile.Preface.OfType<Http2PriorityFrame>().ToList();

        return string.Join('|',
            string.Join(';', settings.Select(static s => string.Create(CultureInfo.InvariantCulture, $"{s.Id}:{s.Value}"))),
            windowUpdate is null ? "00" : windowUpdate.Increment.ToString(CultureInfo.InvariantCulture),
            priorities.Count == 0
                ? "0"
                : string.Join(',', priorities.Select(static p => string.Create(CultureInfo.InvariantCulture,
                    $"{p.StreamId}:{(p.Exclusive ? 1 : 0)}:{p.DependencyStreamId}:{p.Weight + 1}"))),
            string.Join(',', profile.PseudoHeaderOrder.Select(static header => header switch
            {
                PseudoHeader.Method => "m",
                PseudoHeader.Authority => "a",
                PseudoHeader.Scheme => "s",
                PseudoHeader.Path => "p",
                _ => throw new ArgumentOutOfRangeException(nameof(profile), header, null),
            })));
    }
}
