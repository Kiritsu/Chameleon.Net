using Chameleon.Net.Inspector.Server;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Analysis;

/// <summary>Matches a client's connection WINDOW_UPDATEs with the <see cref="ConnectionWindowUpdate"/> rules.</summary>
internal static class FlowControlRules
{
    /// <summary>An increment acknowledges everything consumed when the threshold was crossed, so it exceeds the threshold by at most
    /// what the read that crossed it consumed.</summary>
    private const long ReadSlack = 65536;

    /// <summary>The connection WINDOW_UPDATE increments the client sent on this connection.</summary>
    public static List<long> ConnectionIncrements(ConnectionCapture connection) =>
        [.. connection.Http2Events().Where(static e => e is { Type: "WINDOW_UPDATE", StreamId: 0, Value: not null }).Select(static e => e.Value!.Value)];

    /// <summary>Bytes consumed before the connection is acknowledged, under this rule and the client's preface.</summary>
    public static long Threshold(Http2Profile http2, ConnectionWindowUpdate rule) => rule == ConnectionWindowUpdate.HalfOfConnectionWindow
        ? http2.ConnectionWindow / 2
        : StreamWindow(http2) / 2;

    public static bool Matches(IEnumerable<long> increments, long threshold) =>
        increments.All(increment => increment >= threshold && increment < threshold + ReadSlack);

    /// <summary>SETTINGS_INITIAL_WINDOW_SIZE from the preface, or the protocol default.</summary>
    private static long StreamWindow(Http2Profile http2) =>
        http2.Preface.OfType<Http2SettingsFrame>().SelectMany(static frame => frame.Settings).LastOrDefault(static s => s.Id == 4) is { Id: 4 } setting
            ? setting.Value
            : 65535;
}
