using System.Buffers;

namespace Chameleon.Net.Http;

internal static class HeaderValidation
{
    private static readonly SearchValues<char> TokenChars =
        SearchValues.Create("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

    /// <exception cref="ArgumentException">The name is not a token, or the value contains CR, LF or NUL (header injection).</exception>
    public static void Validate(IEnumerable<KeyValuePair<string, string>> headers)
    {
        foreach (var (name, value) in headers)
        {
            if (name.Length == 0 || name.AsSpan().ContainsAnyExcept(TokenChars))
            {
                throw new ArgumentException($"'{name}' is not a valid header name.", nameof(headers));
            }

            if (value.AsSpan().ContainsAny('\r', '\n', '\0'))
            {
                throw new ArgumentException($"The value of header '{name}' contains CR, LF or NUL.", nameof(headers));
            }
        }
    }
}
