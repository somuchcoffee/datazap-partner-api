using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web;

// Asks the OS for a free port and releases it. HttpListener cannot bind port 0 itself,
// so another process could grab the port in between. Rare enough that the sample does
// not retry; wrap Start() in a small retry loop if you want to close that window.
public static int FreeLoopbackPort()
{
    var probe = new TcpListener(IPAddress.Loopback, 0);
    probe.Start();
    var port = ((IPEndPoint)probe.LocalEndpoint).Port;
    probe.Stop();
    return port;
}

// redirectUri is the exact "http://127.0.0.1:{port}/callback" from the authorize URL
public static async Task<string> RunConsentOnLoopbackAsync(
    Uri authorizeUrl, string redirectUri, string expectedState, CancellationToken ct)
{
    var port = new Uri(redirectUri).Port;
    using var listener = new HttpListener();
    listener.Prefixes.Add($"http://127.0.0.1:{port}/");   // root prefix, path checked below
    listener.Start();

    Process.Start(new ProcessStartInfo(authorizeUrl.ToString()) { UseShellExecute = true });

    while (true)
    {
        var context = await listener.GetContextAsync().WaitAsync(ct);   // ct bounds the wait
        if (context.Request.Url?.AbsolutePath != "/callback")
        {
            context.Response.StatusCode = 404;
            context.Response.Close();
            continue;
        }

        var query = HttpUtility.ParseQueryString(context.Request.Url.Query);
        var html = "<html><body>Done. You can return to the app.</body></html>";
        var bytes = Encoding.UTF8.GetBytes(html);
        context.Response.ContentType = "text/html";
        await context.Response.OutputStream.WriteAsync(bytes);
        context.Response.Close();

        if (query["state"] != expectedState)
            throw new DatazapAuthException("State mismatch. Discard this response.");
        if (query["error"] is { } error)
            throw new DatazapAuthException(error == "access_denied"
                ? "The user declined."
                : query["error_description"] ?? error);
        return query["code"]
            ?? throw new DatazapAuthException("No authorization code in the callback.");
    }
}
