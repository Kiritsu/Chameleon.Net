namespace Chameleon.Net.Fingerprints;

/// <summary>JA3 is order-sensitive and unstable for Chrome ≥110; JA4 (sorted) and JA4_r (raw) are the targets.</summary>
public sealed record TlsFingerprint(string Ja3, string Ja3Hash, string Ja4, string Ja4Raw);
