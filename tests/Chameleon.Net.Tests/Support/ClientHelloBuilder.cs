namespace Chameleon.Net.Tests.Support;

/// <summary>Assembles ClientHello records byte by byte, independent of BouncyCastle and of the library's encoder, so parser/fingerprinter tests don't validate code against itself.</summary>
internal static class ClientHelloBuilder
{
    public static byte[] Record(ushort handshakeVersion, ushort[] cipherSuites, params byte[][] extensions)
    {
        var body = new List<byte>();
        AddUInt16(body, handshakeVersion);
        body.AddRange(new byte[32]);
        body.Add(0);
        AddUInt16(body, cipherSuites.Length * 2);
        foreach (var suite in cipherSuites)
        {
            AddUInt16(body, suite);
        }

        body.Add(1);
        body.Add(0);
        var extensionBytes = extensions.SelectMany(static e => e).ToArray();
        AddUInt16(body, extensionBytes.Length);
        body.AddRange(extensionBytes);

        var handshake = new List<byte> { 1, (byte)(body.Count >> 16), (byte)(body.Count >> 8), (byte)body.Count };
        handshake.AddRange(body);

        var record = new List<byte> { 22, 0x03, 0x01 };
        AddUInt16(record, handshake.Count);
        record.AddRange(handshake);
        return [.. record];
    }

    public static byte[] Extension(ushort type, params byte[] data)
    {
        var bytes = new List<byte>();
        AddUInt16(bytes, type);
        AddUInt16(bytes, data.Length);
        bytes.AddRange(data);
        return [.. bytes];
    }

    public static byte[] UInt16List(params ushort[] values)
    {
        var bytes = new List<byte>();
        AddUInt16(bytes, values.Length * 2);
        foreach (var value in values)
        {
            AddUInt16(bytes, value);
        }

        return [.. bytes];
    }

    public static byte[] SupportedVersions(params ushort[] versions)
    {
        var bytes = new List<byte> { (byte)(versions.Length * 2) };
        foreach (var version in versions)
        {
            AddUInt16(bytes, version);
        }

        return [.. bytes];
    }

    public static byte[] PointFormats(params byte[] formats) => [(byte)formats.Length, .. formats];

    public static byte[] Alpn(params byte[][] protocols)
    {
        var list = new List<byte>();
        foreach (var protocol in protocols)
        {
            list.Add((byte)protocol.Length);
            list.AddRange(protocol);
        }

        var bytes = new List<byte>();
        AddUInt16(bytes, list.Count);
        bytes.AddRange(list);
        return [.. bytes];
    }

    public static byte[] Alpn(params string[] protocols) =>
        Alpn(protocols.Select(static p => System.Text.Encoding.ASCII.GetBytes(p)).ToArray());

    private static void AddUInt16(List<byte> bytes, int value)
    {
        bytes.Add((byte)(value >> 8));
        bytes.Add((byte)value);
    }
}
