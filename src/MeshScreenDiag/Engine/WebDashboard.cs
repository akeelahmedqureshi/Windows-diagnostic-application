using System.Net;
using System.Net.Sockets;
using System.Text;
using MeshScreenDiag.Core.Reporting;

namespace MeshScreenDiag.Engine;

/// <summary>
/// Tiny read-only HTTP dashboard bound to 127.0.0.1. When the remote desktop is black, the technician can
/// still open it through MeshCentral's port mapping ("Web-HTTP" / relay link to localhost:PORT) and see the
/// live diagnosis, place a black-screen marker and download the report.
/// </summary>
internal sealed class WebDashboard : IDisposable
{
    private readonly MonitorEngine _engine;
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();

    public WebDashboard(MonitorEngine engine, int port)
    {
        _engine = engine;
        Port = port;
        _listener = new TcpListener(IPAddress.Loopback, port);
    }

    public int Port { get; }
    public string Url => $"http://127.0.0.1:{Port}/";

    public void Start()
    {
        _listener.Start();
        _ = Task.Run(AcceptLoop);
    }

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch
            {
                break;
            }
            _ = Task.Run(() => Handle(client));
        }
    }

    private async Task Handle(TcpClient client)
    {
        using (client)
        {
            try
            {
                client.ReceiveTimeout = 5000;
                var stream = client.GetStream();
                using var reader = new StreamReader(stream, Encoding.ASCII, false, 4096, leaveOpen: true);
                var requestLine = await reader.ReadLineAsync();
                if (string.IsNullOrEmpty(requestLine)) return;
                string? line;
                while (!string.IsNullOrEmpty(line = await reader.ReadLineAsync()))
                {
                    // Headers are not needed.
                }

                var parts = requestLine.Split(' ');
                var method = parts[0];
                var path = parts.Length > 1 ? parts[1].Split('?')[0] : "/";

                switch (method, path)
                {
                    case ("GET", "/"):
                        await Send(stream, 200, "text/html; charset=utf-8", BuildPage());
                        break;
                    case ("GET", "/report.json"):
                        await Send(stream, 200, "application/json; charset=utf-8", _engine.BuildReport().ToJson());
                        break;
                    case ("GET", "/summary.txt"):
                        await Send(stream, 200, "text/plain; charset=utf-8", TextSummaryBuilder.Build(_engine.BuildReport()));
                        break;
                    case ("GET", "/report.html"):
                        await Send(stream, 200, "text/html; charset=utf-8", new HtmlReportBuilder(_engine.BuildReport()).Build());
                        break;
                    case ("POST", "/mark"):
                        _engine.AddMarker("marked from the web dashboard", automatic: false);
                        await Redirect(stream, "/");
                        break;
                    case ("POST", "/baseline"):
                        await _engine.TakeBaselineAsync();
                        await Redirect(stream, "/");
                        break;
                    case ("POST", "/save"):
                        _engine.SaveReport();
                        await Redirect(stream, "/");
                        break;
                    default:
                        await Send(stream, 404, "text/plain", "Not found");
                        break;
                }
            }
            catch
            {
                // Client went away; nothing to do.
            }
        }
    }

    private string BuildPage()
    {
        var report = _engine.BuildReport();
        var html = new HtmlReportBuilder(report).Build(autoRefreshSeconds: 5);
        const string toolbar =
            "<div style=\"margin-top:8px;display:flex;gap:6px;flex-wrap:wrap\">" +
            "<form method=\"post\" action=\"/mark\"><button style=\"background:#c62828;color:#fff;border:0;padding:6px 12px;border-radius:4px;font-weight:700;cursor:pointer\">Screen went black NOW</button></form>" +
            "<form method=\"post\" action=\"/baseline\"><button style=\"padding:6px 12px;border-radius:4px;cursor:pointer\">Take baseline</button></form>" +
            "<form method=\"post\" action=\"/save\"><button style=\"padding:6px 12px;border-radius:4px;cursor:pointer\">Save report to disk</button></form>" +
            "<a href=\"/report.html\" style=\"color:#fff;padding:6px\">Static report</a><a href=\"/report.json\" style=\"color:#fff;padding:6px\">JSON</a><a href=\"/summary.txt\" style=\"color:#fff;padding:6px\">Text summary</a>" +
            "<span style=\"color:#c9d1e0;padding:6px\">Live view — refreshes every 5 s</span></div>";
        return html.Replace("</header>", toolbar + "</header>");
    }

    private static async Task Send(NetworkStream stream, int status, string contentType, string body)
    {
        var bytes = Encoding.UTF8.GetBytes(body);
        var header = $"HTTP/1.1 {status} {(status == 200 ? "OK" : "Not Found")}\r\nContent-Type: {contentType}\r\nContent-Length: {bytes.Length}\r\n" +
                     "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(header));
        await stream.WriteAsync(bytes);
    }

    private static async Task Redirect(NetworkStream stream, string location)
    {
        var header = $"HTTP/1.1 303 See Other\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(header));
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _listener.Stop(); } catch { /* already stopped */ }
    }
}
