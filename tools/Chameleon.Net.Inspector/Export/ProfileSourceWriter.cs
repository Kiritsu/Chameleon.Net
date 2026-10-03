using System.Globalization;
using System.Text;
using Chameleon.Net.Profiles;

namespace Chameleon.Net.Inspector.Export;

/// <summary>Writes an exported profile as C# in the style of the built-in profiles, ready to paste into a project.</summary>
internal static class ProfileSourceWriter
{
    private const int LineWidth = 140;

    public static string Write(ExportedProfile export, IEnumerable<string> header)
    {
        var profile = export.Profile;
        var source = new StringBuilder();
        foreach (var line in header.Concat(export.Notes.Select(static n => $"- {n}")))
        {
            source.Append("// ").AppendLine(line);
        }

        source.AppendLine()
            .AppendLine("using System.Collections.Generic;")
            .AppendLine("using Chameleon.Net.Profiles;")
            .AppendLine()
            .AppendLine("public static class ExportedProfiles")
            .AppendLine("{")
            .AppendLine(CultureInfo.InvariantCulture, $"    public static ClientProfile {export.PropertyName} {{ get; }} = new(")
            .AppendLine(CultureInfo.InvariantCulture, $"        Identity: new ProfileIdentity({Literal(profile.Identity.Name)}, ClientPlatform.{profile.Identity.Platform}, {Literal(profile.Identity.ClientFamily)}, {Literal(profile.Identity.Version)}),");
        WriteTls(source, profile.Tls);
        WriteHttp2(source, profile.Http2);
        WriteHeaders(source, profile.Headers);
        WriteWebSocket(source, profile.WebSocket);
        source.AppendLine("}");
        return source.ToString();
    }

    private static void WriteTls(StringBuilder source, TlsProfile tls)
    {
        source.AppendLine("        Tls: new TlsProfile(");
        List(source, "            CipherSuites: ", tls.CipherSuites.Select(static c => c.ToString(CultureInfo.InvariantCulture)), ",");
        source.AppendLine("            Extensions:").AppendLine("            [");
        foreach (var extension in tls.Extensions)
        {
            source.Append("                ").Append(Extension(extension)).AppendLine(",");
        }

        source.AppendLine("            ],")
            .AppendLine(CultureInfo.InvariantCulture, $"            Shuffle: ExtensionShufflePolicy.{tls.Shuffle},")
            .AppendLine(CultureInfo.InvariantCulture, $"            Grease: {Grease(tls.Grease)}),");
    }

    private static void WriteHttp2(StringBuilder source, Http2Profile http2)
    {
        source.AppendLine("        Http2: new Http2Profile(");
        if (http2.Preface.Count == 0)
        {
            source.AppendLine("            Preface: [],");
        }
        else
        {
            source.AppendLine("            Preface:").AppendLine("            [");
            foreach (var frame in http2.Preface)
            {
                source.Append("                ").Append(frame switch
                {
                    Http2SettingsFrame settings => $"new Http2SettingsFrame([{string.Join(", ", settings.Settings.Select(static s => $"new Http2Setting({s.Id}, {s.Value})"))}])",
                    Http2WindowUpdateFrame update => $"new Http2WindowUpdateFrame({update.Increment})",
                    Http2PriorityFrame priority => $"new Http2PriorityFrame({priority.StreamId}, {priority.DependencyStreamId}, {priority.Weight}, {Bool(priority.Exclusive)})",
                    _ => throw new NotSupportedException(frame.GetType().Name),
                }).AppendLine(",");
            }

            source.AppendLine("            ],");
        }

        source.AppendLine(CultureInfo.InvariantCulture, $"            PseudoHeaderOrder: [{string.Join(", ", http2.PseudoHeaderOrder.Select(static p => $"PseudoHeader.{p}"))}],")
            .AppendLine(CultureInfo.InvariantCulture, $"            HeadersPriority: {Priority(http2.HeadersPriority)},");
        if (http2.HeadersPriorityOverrides is { Count: > 0 } overrides)
        {
            source.AppendLine("            HeadersPriorityOverrides: new Dictionary<RequestKind, Http2HeadersPriority>").AppendLine("            {");
            foreach (var (kind, priority) in overrides)
            {
                source.AppendLine(CultureInfo.InvariantCulture, $"                [RequestKind.{kind}] = {Priority(priority)},");
            }

            source.AppendLine("            },");
        }

        source.AppendLine(CultureInfo.InvariantCulture, $"            FirstStreamId: {http2.FirstStreamId}),");
    }

    private static void WriteHeaders(StringBuilder source, HeaderProfile headers)
    {
        source.AppendLine("        Headers: new HeaderProfile(");
        List(source, "            HeaderOrder: ", headers.HeaderOrder.Select(Literal), ",");
        if (headers.Overrides.Count == 0)
        {
            source.AppendLine("            Overrides: new Dictionary<RequestKind, IReadOnlyList<string>>(),");
        }
        else
        {
            source.AppendLine("            Overrides: new Dictionary<RequestKind, IReadOnlyList<string>>").AppendLine("            {");
            foreach (var (kind, order) in headers.Overrides)
            {
                List(source, $"                [RequestKind.{kind}] = ", order.Select(Literal), ",");
            }

            source.AppendLine("            },");
        }

        source.AppendLine(CultureInfo.InvariantCulture, $"            Http1Casing: HeaderCasing.{headers.Http1Casing},");
        source.Append("            DefaultHeaders: ");
        Dictionary(source, headers.DefaultHeaders, "            ");
        source.AppendLine(",").AppendLine(CultureInfo.InvariantCulture, $"            OrderMode: HeaderOrderMode.{headers.OrderMode},");
        if (headers.DefaultHeaderOverrides is { Count: > 0 } overrides)
        {
            source.AppendLine("            DefaultHeaderOverrides: new Dictionary<RequestKind, IReadOnlyDictionary<string, string>>").AppendLine("            {");
            foreach (var (kind, defaults) in overrides)
            {
                source.Append(CultureInfo.InvariantCulture, $"                [RequestKind.{kind}] = ");
                Dictionary(source, defaults, "                ");
                source.AppendLine(",");
            }

            source.AppendLine("            },");
        }
        else
        {
            source.AppendLine("            DefaultHeaderOverrides: null,");
        }

        source.AppendLine(CultureInfo.InvariantCulture, $"            Http2OnlyHeaders: {(headers.Http2OnlyHeaders is null ? "null" : $"[{string.Join(", ", headers.Http2OnlyHeaders.Select(Literal))}]")}),");
    }

    private static void WriteWebSocket(StringBuilder source, WebSocketProfile webSocket)
    {
        source.AppendLine("        WebSocket: new WebSocketProfile(");
        List(source, "            HandshakeHeaderOrder: ", webSocket.HandshakeHeaderOrder.Select(Literal), ",");
        source.AppendLine(CultureInfo.InvariantCulture, $"            PerMessageDeflateOffer: {(webSocket.PerMessageDeflateOffer is null ? "null" : Literal(webSocket.PerMessageDeflateOffer))},")
            .AppendLine(CultureInfo.InvariantCulture, $"            Alpn: {(webSocket.Alpn is null ? "null" : $"[{string.Join(", ", webSocket.Alpn.Select(Literal))}]")}));");
    }

    private static string Extension(TlsExtension extension) => extension switch
    {
        GreaseExtension grease => grease.Body.IsEmpty ? "new GreaseExtension()" : $"new GreaseExtension(new byte[] {{ {Bytes(grease.Body.Span)} }})",
        ServerNameExtension => "new ServerNameExtension()",
        StatusRequestExtension => "new StatusRequestExtension()",
        SupportedGroupsExtension groups => $"new SupportedGroupsExtension([{Groups(groups.Groups)}])",
        EcPointFormatsExtension formats => $"new EcPointFormatsExtension([{Bytes(formats.Formats.ToArray())}])",
        SignatureAlgorithmsExtension schemes => $"new SignatureAlgorithmsExtension([{Hex(schemes.Schemes)}])",
        AlpnExtension alpn => $"new AlpnExtension([{string.Join(", ", alpn.Protocols.Select(Literal))}])",
        SignedCertificateTimestampExtension => "new SignedCertificateTimestampExtension()",
        PaddingExtension padding => $"new PaddingExtension(TargetClientHelloLength: {padding.TargetClientHelloLength})",
        ExtendedMasterSecretExtension => "new ExtendedMasterSecretExtension()",
        CompressCertificateExtension compression => $"new CompressCertificateExtension([{string.Join(", ", compression.Algorithms)}])",
        RecordSizeLimitExtension limit => $"new RecordSizeLimitExtension(0x{limit.Limit:X4})",
        DelegatedCredentialsExtension credentials => $"new DelegatedCredentialsExtension([{Hex(credentials.Schemes)}])",
        SessionTicketExtension => "new SessionTicketExtension()",
        SupportedVersionsExtension versions => $"new SupportedVersionsExtension([{Hex(versions.Versions)}])",
        PskKeyExchangeModesExtension modes => $"new PskKeyExchangeModesExtension([{Bytes(modes.Modes.ToArray())}])",
        KeyShareExtension shares => $"new KeyShareExtension([{Groups(shares.Groups)}])",
        ApplicationSettingsExtension alps => $"new ApplicationSettingsExtension([{string.Join(", ", alps.Protocols.Select(Literal))}], Codepoint: {alps.Codepoint})",
        EncryptedClientHelloGreaseExtension { AeadIds: null, PayloadLengths: null } => "new EncryptedClientHelloGreaseExtension()",
        EncryptedClientHelloGreaseExtension ech =>
            $"new EncryptedClientHelloGreaseExtension(AeadIds: {(ech.AeadIds is null ? "null" : $"[{Hex(ech.AeadIds)}]")}, PayloadLengths: {(ech.PayloadLengths is null ? "null" : $"[{string.Join(", ", ech.PayloadLengths)}]")})",
        RenegotiationInfoExtension => "new RenegotiationInfoExtension()",
        RawExtension raw => $"new RawExtension({raw.Type}, new byte[] {{ {Bytes(raw.Body.Span)} }})",
        _ => throw new NotSupportedException(extension.GetType().Name),
    };

    private static string Grease(GreasePlacement grease) => grease == GreasePlacement.None
        ? "GreasePlacement.None"
        : string.Join(" | ", Enum.GetValues<GreasePlacement>().Where(g => g != GreasePlacement.None && grease.HasFlag(g)).Select(static g => $"GreasePlacement.{g}"));

    private static string Priority(Http2HeadersPriority? priority) =>
        priority is { } p ? $"new Http2HeadersPriority({p.DependencyStreamId}, {p.Weight}, {Bool(p.Exclusive)})" : "null";

    /// <summary>A bracketed list on one line, or one item per line when too long.</summary>
    private static void List(StringBuilder source, string prefix, IEnumerable<string> items, string suffix)
    {
        var values = items.ToList();
        var line = $"{prefix}[{string.Join(", ", values)}]{suffix}";
        if (line.Length <= LineWidth)
        {
            source.AppendLine(line);
            return;
        }

        var indent = new string(' ', prefix.Length - prefix.TrimStart().Length);
        source.AppendLine(prefix.TrimEnd()).Append(indent).AppendLine("[");
        var current = new StringBuilder(indent + "    ");
        foreach (var value in values)
        {
            if (current.Length + value.Length + 2 > LineWidth && current.Length > indent.Length + 4)
            {
                source.AppendLine(current.ToString().TrimEnd());
                current.Clear().Append(indent).Append("    ");
            }

            current.Append(value).Append(", ");
        }

        source.AppendLine(current.ToString().TrimEnd()).Append(indent).Append(']').AppendLine(suffix);
    }

    private static void Dictionary(StringBuilder source, IReadOnlyDictionary<string, string> values, string indent)
    {
        source.AppendLine("new Dictionary<string, string>").Append(indent).AppendLine("{");
        foreach (var (name, value) in values)
        {
            source.Append(indent).AppendLine(CultureInfo.InvariantCulture, $"    [{Literal(name)}] = {Literal(value)},");
        }

        source.Append(indent).Append('}');
    }

    private static string Groups(IEnumerable<ushort> groups) =>
        string.Join(", ", groups.Select(static g => g > 0xFF ? $"0x{g:X4}" : g.ToString(CultureInfo.InvariantCulture)));

    private static string Hex(IEnumerable<ushort> values) => string.Join(", ", values.Select(static v => $"0x{v:X4}"));

    private static string Bytes(ReadOnlySpan<byte> bytes)
    {
        var values = new List<string>(bytes.Length);
        foreach (var b in bytes)
        {
            values.Add(b.ToString(CultureInfo.InvariantCulture));
        }

        return string.Join(", ", values);
    }

    private static string Bool(bool value) => value ? "true" : "false";

    public static string Literal(string value)
    {
        var literal = new StringBuilder("\"");
        foreach (var c in value)
        {
            literal.Append(c switch
            {
                '"' => "\\\"",
                '\\' => "\\\\",
                _ when char.IsControl(c) || c > '~' => $"\\u{(int)c:X4}",
                _ => c.ToString(),
            });
        }

        return literal.Append('"').ToString();
    }
}
