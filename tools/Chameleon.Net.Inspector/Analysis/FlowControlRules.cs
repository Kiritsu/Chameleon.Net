using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Analysis;

/// <summary>Matches a client's connection WINDOW_UPDATEs with the <see cref="Http2FlowControl"/> rules.</summary>
internal static class FlowControlRules
{
    /// <summary>An increment acknowledges everything consumed when the threshold was crossed, so it exceeds the threshold by at most
    /// what the read that crossed it consumed.</summary>
    private const long ReadSlack = 65536;

    /// <summary>Chromium's 5 seconds, measured by the client; a little less here for the time frames take to arrive.</summary>
    private const double SmallUpdateDelayMilliseconds = 4500;

    /// <summary>What the client's connection WINDOW_UPDATEs say about a rule.</summary>
    /// <param name="Explained">Every one of them follows the rule.</param>
    /// <param name="AtThreshold">How many were sent for crossing the threshold: the evidence the rule is the client's.</param>
    /// <param name="Increments">The increments, for messages.</param>
    public readonly record struct Verdict(bool Explained, int AtThreshold, IReadOnlyList<long> Increments);

    /// <summary>Bytes consumed before the connection is acknowledged, under this rule and the client's preface.</summary>
    public static long Threshold(Http2Profile http2, Http2FlowControl rule) => rule == Http2FlowControl.Chromium
        ? http2.ConnectionWindow / 2
        : StreamWindow(http2) / 2;

    /// <summary>Judges the connection WINDOW_UPDATEs of these connections, in the order each one sent them. An increment past the threshold
    /// and its slack is explained by a stream the client reset since the previous one (its buffered bytes are acknowledged at once); one
    /// below it, under Chromium's rule, by 5 seconds without a connection WINDOW_UPDATE.</summary>
    public static Verdict Judge(IEnumerable<ConnectionCapture> connections, Http2Profile http2, Http2FlowControl rule)
    {
        var threshold = Threshold(http2, rule);
        var increments = new List<long>();
        var explained = true;
        var atThreshold = 0;
        foreach (var connection in connections)
        {
            var lastUpdate = 0.0;
            var resetSinceLastUpdate = false;
            foreach (var e in connection.Http2Events())
            {
                if (e.Type == "RST_STREAM")
                {
                    resetSinceLastUpdate = true;
                    continue;
                }

                if (e is not { Type: "WINDOW_UPDATE", StreamId: 0, Value: { } increment })
                {
                    continue;
                }

                increments.Add(increment);
                var crossed = rule == Http2FlowControl.Chromium ? increment > threshold : increment >= threshold;
                if (crossed && (increment < threshold + ReadSlack || resetSinceLastUpdate))
                {
                    atThreshold++;
                }
                else if (crossed || rule != Http2FlowControl.Chromium || e.At - lastUpdate < SmallUpdateDelayMilliseconds)
                {
                    explained = false;
                }

                lastUpdate = e.At;
                resetSinceLastUpdate = false;
            }
        }

        return new Verdict(explained, atThreshold, increments);
    }

    /// <summary>SETTINGS_INITIAL_WINDOW_SIZE from the preface, or the protocol default.</summary>
    private static long StreamWindow(Http2Profile http2) =>
        http2.Preface.OfType<Http2SettingsFrame>().SelectMany(static frame => frame.Settings).LastOrDefault(static s => s.Id == 4) is { Id: 4 } setting
            ? setting.Value
            : 65535;
}
