using System.Globalization;
using System.Net.WebSockets;

namespace Chameleon.Net.WebSockets;

/// <summary>RFC 7692 negotiation, client side: turns the server's accepted <c>permessage-deflate</c> parameters into BCL options.</summary>
internal static class PerMessageDeflate
{
    /// <exception cref="WebSocketException">The server accepted an extension that was not offered, or parameters the BCL cannot honour.</exception>
    public static WebSocketDeflateOptions? Negotiate(IEnumerable<string> acceptedExtensionHeaders, bool offered)
    {
        WebSocketDeflateOptions? options = null;

        foreach (var extension in acceptedExtensionHeaders.SelectMany(static header =>
                     header.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)))
        {
            var parts = extension.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            if (!string.Equals(parts[0], "permessage-deflate", StringComparison.OrdinalIgnoreCase) || !offered || options is not null)
            {
                throw HeaderError($"The server accepted extension '{parts[0]}', which was not offered.");
            }

            options = new WebSocketDeflateOptions();
            foreach (var parameter in parts.AsSpan(1))
            {
                var separator = parameter.IndexOf('=', StringComparison.Ordinal);
                var name = (separator < 0 ? parameter : parameter[..separator]).Trim();
                var value = separator < 0 ? null : parameter[(separator + 1)..].Trim().Trim('"');

                switch (name.ToLowerInvariant())
                {
                    case "client_no_context_takeover":
                        options.ClientContextTakeover = false;
                        break;
                    case "server_no_context_takeover":
                        options.ServerContextTakeover = false;
                        break;
                    case "client_max_window_bits":
                        options.ClientMaxWindowBits = WindowBits(name, value);
                        break;
                    case "server_max_window_bits":
                        options.ServerMaxWindowBits = WindowBits(name, value);
                        break;
                    default:
                        throw HeaderError($"Unknown permessage-deflate parameter '{name}'.");
                }
            }
        }

        return options;
    }

    // The BCL's zlib-based implementation supports 9..15; RFC 7692 also allows 8.
    private static int WindowBits(string name, string? value) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var bits) && bits is >= 9 and <= 15
            ? bits
            : throw HeaderError($"Unsupported permessage-deflate {name} '{value}'.");

    private static WebSocketException HeaderError(string message) => new(WebSocketError.HeaderError, message);
}
