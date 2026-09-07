namespace Chameleon.Net.Fingerprints;

public interface IClientHelloParser
{
    ParsedClientHello Parse(ReadOnlySpan<byte> tlsRecord);
}
