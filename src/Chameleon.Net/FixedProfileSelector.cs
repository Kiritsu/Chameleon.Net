using Chameleon.Net.Http;
using Chameleon.Net.Profiles;

namespace Chameleon.Net;

/// <summary>Every connection uses the same profile.</summary>
public sealed class FixedProfileSelector : IProfileSelector
{
    private readonly ClientProfile _profile;

    public FixedProfileSelector(ClientProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        _profile = profile;
    }

    public ClientProfile SelectForConnection(Origin origin) => _profile;
}
