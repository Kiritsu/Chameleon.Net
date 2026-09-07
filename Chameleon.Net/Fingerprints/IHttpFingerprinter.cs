using Chameleon.Net.Profiles;

namespace Chameleon.Net.Fingerprints;

public interface IHttpFingerprinter
{
    string ComputeJa4H(Version httpVersion, string method, IReadOnlyList<KeyValuePair<string, string>> headers);

    string ComputeAkamai(IReadOnlyList<Http2PrefaceFrame> preface, IReadOnlyList<PseudoHeader> pseudoHeaderOrder);
}
