namespace Chameleon.Net.Http;

public readonly record struct Origin(string Scheme, string Host, int Port);
