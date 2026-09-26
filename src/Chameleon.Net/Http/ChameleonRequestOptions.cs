using Chameleon.Net.Profiles;

namespace Chameleon.Net.Http;

/// <summary>Per-request settings, set through <see cref="HttpRequestMessage.Options"/>.</summary>
public static class ChameleonRequestOptions
{
    /// <summary>Selects the header order when the profile distinguishes request kinds (browsers). Defaults to <see cref="RequestKind.Fetch"/>.
    /// <code>request.Options.Set(ChameleonRequestOptions.Kind, RequestKind.Navigate);</code></summary>
    public static HttpRequestOptionsKey<RequestKind> Kind { get; } = new("Chameleon.Net.RequestKind");
}
