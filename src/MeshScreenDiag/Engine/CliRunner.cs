using MeshScreenDiag.Core.Reporting;

namespace MeshScreenDiag.Engine;

/// <summary>
/// Headless modes, e.g. from MeshCentral's Terminal (use <c>start /wait</c> so cmd waits for the output):
/// <code>
///   MeshScreenDiag.exe --snapshot                 one full snapshot + report, then exit
///   MeshScreenDiag.exe --monitor --duration 600   baseline now, monitor 10 minutes, report at the end
///   MeshScreenDiag.exe --mark "client opened X"   place a marker in a running instance
/// </code>
/// </summary>
internal static class CliRunner
{
    public const string Usage = @"MeshCentral Screen Diagnostic

Usage:
  MeshScreenDiag.exe                       Start the desktop dashboard
  MeshScreenDiag.exe --snapshot [options]  Collect one full snapshot, write a report and exit
  MeshScreenDiag.exe --monitor  [options]  Take a baseline, monitor, write reports (Ctrl+C to stop)
  MeshScreenDiag.exe --mark [""note""]       Place a black-screen marker in the running instance
  MeshScreenDiag.exe --help

Options:
  --out <folder>          Report folder (default C:\ProgramData\MeshScreenDiag)
  --duration <seconds>    Monitoring duration (default: until Ctrl+C or a 'stop.request' file)
  --interval <seconds>    Sampling interval (default 2)
  --web <port>            Serve the live dashboard on http://127.0.0.1:<port>/
  --agent-name <name>     Extra (branded) MeshCentral agent process/service name
  --redact                Redact window titles in reports
  --no-baseline           Do not take a baseline at start (monitor mode)

Run it inside the user's session (not as SYSTEM in session 0): window, desktop and
capture checks only see the desktop of the session they run in.";

    public static bool IsCliInvocation(string[] args) =>
        args.Any(a => a is "--snapshot" or "--monitor" or "--mark" or "--help" or "-h" or "/?");

    public static int Run(string[] args)
    {
        if (args.Any(a => a is "--help" or "-h" or "/?"))
        {
            Console.WriteLine(Usage);
            return 0;
        }

        var settings = AppSettings.Load();
        string? Arg(string name) { var i = Array.IndexOf(args, name); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
        if (Arg("--out") is { } outDir) settings.ReportFolder = outDir;
        if (int.TryParse(Arg("--interval"), out var interval)) settings.FastIntervalSeconds = interval;
        if (int.TryParse(Arg("--web"), out var port)) settings.WebPort = port;
        if (Arg("--agent-name") is { } agent) settings.ExtraAgentNames = string.Join(",", new[] { settings.ExtraAgentNames, agent }.Where(s => !string.IsNullOrWhiteSpace(s)));
        if (args.Contains("--redact")) settings.RedactWindowTitles = true;
        settings.Normalize();

        if (args.Contains("--mark"))
        {
            var note = Arg("--mark");
            Directory.CreateDirectory(settings.ReportFolder);
            File.WriteAllText(Path.Combine(settings.ReportFolder, "mark.request"), note is { } n && !n.StartsWith("--") ? n : "marked from command line");
            Console.WriteLine("Marker request written; the running MeshScreenDiag instance will pick it up within a few seconds.");
            return 0;
        }

        using var engine = new MonitorEngine(settings);
        engine.Log += Console.WriteLine;

        if (args.Contains("--snapshot"))
        {
            Console.WriteLine("Collecting full snapshot...");
            engine.RefreshNow();
            var paths = engine.SaveReport("Command-line snapshot");
            Console.WriteLine(TextSummaryBuilder.Build(engine.BuildReport()));
            Console.WriteLine($"Report: {paths.Html}\nJSON:   {paths.Json}\nText:   {paths.Text}");
            return 0;
        }

        // --monitor
        var duration = int.TryParse(Arg("--duration"), out var d) ? TimeSpan.FromSeconds(d) : (TimeSpan?)null;
        var stopFile = Path.Combine(settings.ReportFolder, "stop.request");
        using var done = new ManualResetEventSlim();
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; done.Set(); };

        WebDashboard? web = null;
        if (settings.WebPort > 0)
        {
            try
            {
                web = new WebDashboard(engine, settings.WebPort);
                web.Start();
                Console.WriteLine("Live dashboard: " + web.Url);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Web dashboard failed to start: " + ex.Message);
            }
        }

        if (!args.Contains("--no-baseline"))
        {
            Console.WriteLine("Taking baseline snapshot...");
            engine.TakeBaselineAsync().GetAwaiter().GetResult();
        }
        engine.Start();
        Console.WriteLine($"Monitoring{(duration != null ? $" for {duration.Value.TotalSeconds:F0}s" : "")}. " +
                          $"Mark the black screen with: MeshScreenDiag.exe --mark \"note\"   Stop: Ctrl+C or create {stopFile}");
        Console.WriteLine("Live status file: " + engine.StatusFilePath);

        var until = duration != null ? DateTime.UtcNow + duration.Value : DateTime.MaxValue;
        var lastHeadline = "";
        while (!done.IsSet && DateTime.UtcNow < until)
        {
            done.Wait(TimeSpan.FromSeconds(2));
            if (File.Exists(stopFile))
            {
                try { File.Delete(stopFile); } catch { /* ignore */ }
                break;
            }
            var headline = engine.Verdict?.Headline ?? "";
            if (headline != lastHeadline)
            {
                Console.WriteLine($"{DateTime.Now:HH:mm:ss} {headline}");
                lastHeadline = headline;
            }
        }

        engine.Stop();
        web?.Dispose();
        var final = engine.SaveReport("Command-line monitoring session");
        Console.WriteLine(TextSummaryBuilder.Build(engine.BuildReport()));
        Console.WriteLine($"Report: {final.Html}");
        return 0;
    }
}
