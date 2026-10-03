namespace Chameleon.Net.Inspector.Export;

/// <summary>The browser walk-through behind <c>/capture</c>: a navigation and fetch() GET and POST over HTTP/2, a WebSocket, then a
/// navigation and a fetch() over plain HTTP/1.1 (for header casing and HTTP/1.1-only headers), ending on the exported profile.</summary>
internal static class CapturePages
{
    public const string CookieName = "chameleon_capture";

    public static string Start => """
        <!doctype html>
        <html lang="en">
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Chameleon.Net capture</title>
        <body style="font-family: system-ui, sans-serif; margin: 2rem; max-width: 60rem">
        <h1>Capturing this browser</h1>
        <ol id="steps"><li>Navigation over HTTPS</li></ol>
        <script>
        const step = text => document.getElementById('steps').insertAdjacentHTML('beforeend', `<li>${text}</li>`);
        (async () => {
          await fetch('/capture/fetch');
          step('fetch() GET');
          await fetch('/capture/post', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"capture":true}' });
          step('fetch() POST');
          // Three WebSockets, each a new TLS connection: enough to see Chrome's extension shuffle and the GREASE ECH variants.
          for (let i = 1; i <= 3; i++) {
            await new Promise(resolve => {
              const socket = new WebSocket(`wss://${location.host}/capture/ws`);
              socket.onmessage = () => { socket.close(); resolve(); };
              socket.onerror = resolve;
            });
            step(`WebSocket ${i}`);
          }
          step('Navigation over plain HTTP/1.1…');
          location.href = `http://${location.host}/capture/plain`;
        })();
        </script>
        </body>
        </html>
        """;

    public static string Plain => """
        <!doctype html>
        <html lang="en">
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Chameleon.Net profile</title>
        <body style="font-family: system-ui, sans-serif; margin: 2rem">
        <h1>Exported profile</h1>
        <p>Built from this browser's requests to the inspector. Read the comments at the top: they list what couldn't be observed.</p>
        <p><button id="copy">Copy</button> <a id="download" download="ExportedProfile.cs" href="#">Download</a></p>
        <pre id="code" style="background: #f4f4f4; padding: 1rem; overflow: auto">Exporting…</pre>
        <script>
        (async () => {
          await fetch('/capture/fetch-plain');
          const response = await fetch('/profile');
          const code = await response.text();
          document.getElementById('code').textContent = code;
          document.getElementById('download').href = URL.createObjectURL(new Blob([code], { type: 'text/plain' }));
          document.getElementById('copy').onclick = () => navigator.clipboard.writeText(code);
        })();
        </script>
        </body>
        </html>
        """;
}
