namespace Chameleon.Net.Http.Http2.Hpack;

/// <summary>RFC 7541 §5.1 prefixed integers.</summary>
internal static class HpackInteger
{
    public static void Write(List<byte> destination, int value, int prefixBits, byte flags)
    {
        var max = (1 << prefixBits) - 1;
        if (value < max)
        {
            destination.Add((byte)(flags | value));
            return;
        }

        destination.Add((byte)(flags | max));
        value -= max;
        while (value >= 0x80)
        {
            destination.Add((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }

        destination.Add((byte)value);
    }

    /// <exception cref="HpackException">Truncated or larger than <see cref="int.MaxValue"/>.</exception>
    public static int Read(ReadOnlySpan<byte> source, ref int offset, int prefixBits)
    {
        if (offset >= source.Length)
        {
            throw new HpackException("Truncated integer.");
        }

        var max = (1 << prefixBits) - 1;
        var value = source[offset++] & max;
        if (value < max)
        {
            return value;
        }

        for (var shift = 0; ; shift += 7)
        {
            if (offset >= source.Length || shift > 28)
            {
                throw new HpackException("Truncated or oversized integer.");
            }

            var octet = source[offset++];
            var increment = (long)(octet & 0x7F) << shift;
            if (value + increment > int.MaxValue)
            {
                throw new HpackException("Integer overflow.");
            }

            value += (int)increment;
            if ((octet & 0x80) == 0)
            {
                return value;
            }
        }
    }
}
