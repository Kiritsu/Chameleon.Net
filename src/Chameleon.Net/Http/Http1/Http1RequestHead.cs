using System.Text;

namespace Chameleon.Net.Http.Http1;

internal static class Http1RequestHead
{
    /// <summary>Headers are written exactly as given — order and casing are the caller's decision.</summary>
    /// <exception cref="ArgumentException">A header name is not a token, or a value contains CR, LF or NUL (header injection).</exception>
    public static byte[] Encode(string method, string target, IReadOnlyList<KeyValuePair<string, string>> headers)
    {
        HeaderValidation.Validate(headers);

        var head = new StringBuilder();
        head.Append(method).Append(' ').Append(target).Append(" HTTP/1.1\r\n");
        foreach (var (name, value) in headers)
        {
            head.Append(name).Append(": ").Append(value).Append("\r\n");
        }

        head.Append("\r\n");
        return Encoding.Latin1.GetBytes(head.ToString());
    }
}
