using System.ComponentModel;
using System.Text.Json;

namespace MeshScreenDiag.Engine;

/// <summary>User-tunable settings. Shown in a PropertyGrid and persisted as JSON in %LOCALAPPDATA%.</summary>
public sealed class AppSettings
{
    [Category("Monitoring"), DisplayName("Fast interval (seconds)"),
     Description("How often processes, windows, desktop, capture test, network and MeshAgent state are sampled. 2 seconds is a good balance.")]
    public int FastIntervalSeconds { get; set; } = 2;

    [Category("Monitoring"), DisplayName("Full snapshot interval (seconds)"),
     Description("How often services, drivers, firewall rules, security products and GPU adapters are re-read.")]
    public int FullIntervalSeconds { get; set; } = 30;

    [Category("Monitoring"), DisplayName("Event log poll interval (seconds)")]
    public int EventLogIntervalSeconds { get; set; } = 5;

    [Category("Monitoring"), DisplayName("Event log look-back (minutes)"),
     Description("How far back relevant event-log entries are read when monitoring starts.")]
    public int EventLookbackMinutes { get; set; } = 60;

    [Category("Monitoring"), DisplayName("Correlation window (seconds)"),
     Description("Events this many seconds before a black-screen marker are treated as related.")]
    public int CorrelationWindowSeconds { get; set; } = 120;

    [Category("Monitoring"), DisplayName("Auto-mark when capture turns black"),
     Description("Automatically place a black-screen marker (and take an 'after' snapshot) when the capture test turns black.")]
    public bool AutoMarkOnBlack { get; set; } = true;

    [Category("Monitoring"), DisplayName("Auto-save report on black screen"),
     Description("Save a report automatically when a black screen is detected or marked, so it can be downloaded through MeshCentral's Files tab even while the screen is black.")]
    public bool AutoSaveReportOnBlack { get; set; } = true;

    [Category("MeshCentral"), DisplayName("Extra agent process/service names"),
     Description("Comma-separated names of branded/renamed MeshCentral agents (e.g. 'AcmeSupportAgent'). MeshAgent, meshagent* and 'Mesh Agent' are always detected.")]
    public string ExtraAgentNames { get; set; } = "";

    [Category("Reports"), DisplayName("Report folder"),
     Description("Where reports and session logs are written. The default (C:\\ProgramData\\MeshScreenDiag) is easy to reach from MeshCentral's Files tab.")]
    public string ReportFolder { get; set; } = DefaultReportFolder;

    [Category("Reports"), DisplayName("Redact window titles"),
     Description("Replace window titles with [redacted] in saved reports (titles can contain document names, e-mail subjects, etc.).")]
    public bool RedactWindowTitles { get; set; }

    [Category("Remote view"), DisplayName("Local web dashboard port (0 = off)"),
     Description("Serves a read-only live dashboard on http://127.0.0.1:PORT/ . Use MeshCentral's port-mapping / Web-HTTP link to view it while the remote desktop is black. Bound to localhost only.")]
    public int WebPort { get; set; }

    public static string DefaultReportFolder =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "MeshScreenDiag");

    public IReadOnlyList<string> AgentNames =>
        ExtraAgentNames.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string SettingsPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MeshScreenDiag", "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath)) ?? new AppSettings();
        }
        catch
        {
            // Corrupt settings file: fall back to defaults.
        }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
            File.WriteAllText(SettingsPath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            // Settings are a convenience; failing to save them must not break diagnostics.
        }
    }

    public void Normalize()
    {
        FastIntervalSeconds = Math.Clamp(FastIntervalSeconds, 1, 60);
        FullIntervalSeconds = Math.Clamp(FullIntervalSeconds, 10, 600);
        EventLogIntervalSeconds = Math.Clamp(EventLogIntervalSeconds, 2, 120);
        EventLookbackMinutes = Math.Clamp(EventLookbackMinutes, 0, 24 * 60);
        CorrelationWindowSeconds = Math.Clamp(CorrelationWindowSeconds, 10, 1800);
        WebPort = WebPort is < 0 or > 65535 ? 0 : WebPort;
        if (string.IsNullOrWhiteSpace(ReportFolder)) ReportFolder = DefaultReportFolder;
    }
}
