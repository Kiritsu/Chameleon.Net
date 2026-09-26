namespace Chameleon.Net.Http.Http2.Hpack;

/// <summary>A malformed header block. Always a connection error (COMPRESSION_ERROR): the shared dynamic table can no longer be trusted.</summary>
internal sealed class HpackException(string message) : Exception(message);
