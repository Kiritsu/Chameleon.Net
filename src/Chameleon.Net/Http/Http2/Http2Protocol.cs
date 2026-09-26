using System.Buffers.Binary;

namespace Chameleon.Net.Http.Http2;

internal enum Http2FrameType : byte
{
    Data = 0,
    Headers = 1,
    Priority = 2,
    RstStream = 3,
    Settings = 4,
    PushPromise = 5,
    Ping = 6,
    GoAway = 7,
    WindowUpdate = 8,
    Continuation = 9,
}

internal enum Http2ErrorCode : uint
{
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xA,
    EnhanceYourCalm = 0xB,
    InadequateSecurity = 0xC,
    Http11Required = 0xD,
}

internal static class Http2Flags
{
    public const byte EndStream = 0x1;
    public const byte Ack = 0x1;
    public const byte EndHeaders = 0x4;
    public const byte Padded = 0x8;
    public const byte Priority = 0x20;
}

internal static class Http2SettingId
{
    public const ushort HeaderTableSize = 1;
    public const ushort EnablePush = 2;
    public const ushort MaxConcurrentStreams = 3;
    public const ushort InitialWindowSize = 4;
    public const ushort MaxFrameSize = 5;
}

internal readonly record struct Http2FrameHeader(int Length, Http2FrameType Type, byte Flags, int StreamId)
{
    public bool Has(byte flag) => (Flags & flag) != 0;
}

internal static class Http2Frame
{
    public const int HeaderLength = 9;
    public const int DefaultMaxFrameSize = 16384;
    public const int MaxAllowedFrameSize = 16777215;
    public const int DefaultWindowSize = 65535;
    public const int DefaultHeaderTableSize = 4096;

    public static ReadOnlySpan<byte> ClientPreface => "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8;

    public static byte[] Create(Http2FrameType type, byte flags, int streamId, ReadOnlySpan<byte> payload)
    {
        var frame = new byte[HeaderLength + payload.Length];
        WriteHeader(frame, payload.Length, type, flags, streamId);
        payload.CopyTo(frame.AsSpan(HeaderLength));
        return frame;
    }

    public static void WriteHeader(Span<byte> destination, int length, Http2FrameType type, byte flags, int streamId)
    {
        destination[0] = (byte)(length >> 16);
        destination[1] = (byte)(length >> 8);
        destination[2] = (byte)length;
        destination[3] = (byte)type;
        destination[4] = flags;
        BinaryPrimitives.WriteInt32BigEndian(destination[5..], streamId & int.MaxValue);
    }

    public static byte[] Settings(IEnumerable<(ushort Id, uint Value)> settings)
    {
        var payload = new List<byte>();
        foreach (var (id, value) in settings)
        {
            payload.Add((byte)(id >> 8));
            payload.Add((byte)id);
            payload.Add((byte)(value >> 24));
            payload.Add((byte)(value >> 16));
            payload.Add((byte)(value >> 8));
            payload.Add((byte)value);
        }

        return Create(Http2FrameType.Settings, 0, 0, [.. payload]);
    }

    public static byte[] WindowUpdate(int streamId, int increment) => Create(Http2FrameType.WindowUpdate, 0, streamId, UInt32(increment));

    public static byte[] RstStream(int streamId, Http2ErrorCode code) => Create(Http2FrameType.RstStream, 0, streamId, UInt32((int)code));

    public static byte[] GoAway(int lastStreamId, Http2ErrorCode code) => Create(Http2FrameType.GoAway, 0, 0, [.. UInt32(lastStreamId), .. UInt32((int)code)]);

    public static byte[] Priority(int streamId, int dependency, bool exclusive, byte weight) =>
        Create(Http2FrameType.Priority, 0, streamId, PriorityFields(dependency, exclusive, weight));

    /// <summary>The 5 bytes shared by PRIORITY frames and HEADERS frames with the PRIORITY flag. <paramref name="weight"/> is the wire value (weight − 1).</summary>
    public static byte[] PriorityFields(int dependency, bool exclusive, byte weight)
    {
        var fields = new byte[5];
        BinaryPrimitives.WriteUInt32BigEndian(fields, (uint)(dependency & int.MaxValue) | (exclusive ? 0x80000000u : 0));
        fields[4] = weight;
        return fields;
    }

    private static byte[] UInt32(int value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, (uint)value);
        return bytes;
    }
}

/// <summary>A protocol violation by the peer: the connection is closed with GOAWAY carrying <see cref="Code"/>.</summary>
internal sealed class Http2ConnectionException(Http2ErrorCode code, string message) : Exception(message)
{
    public Http2ErrorCode Code { get; } = code;
}

/// <summary>The server did not process the stream (GOAWAY past it, REFUSED_STREAM, or the connection failed before anything was sent).</summary>
internal sealed class Http2RetryableException(string message, Exception? innerException = null) : IOException(message, innerException);
