using System.Reflection;
using System.Text;
using System.Text.Json;
using MeshScreenDiag.Collectors;
using MeshScreenDiag.Core.Analysis;
using MeshScreenDiag.Core.Models;
using MeshScreenDiag.Core.Reporting;
using Microsoft.Win32;

namespace MeshScreenDiag.Engine;

public sealed record ReportPaths(string Html, string Json, string Text);

/// <summary>
/// The monitoring loop. Samples the system on a fixed interval, turns every change into a timeline
/// event, watches for the screen capture turning black, keeps baseline/after snapshots and runs the
/// analysis. All work happens on a background thread at below-normal priority.
/// </summary>
public sealed class MonitorEngine : IDisposable
{
    private const int MaxTimeline = 25000;

    private readonly SnapshotCollector _collector = new();
    private readonly object _gate = new();
    private readonly List<TimelineEvent> _timeline = new();
    private readonly List<EventLogEntryInfo> _events = new();
    private readonly HashSet<string> _eventKeys = new();
    private readonly List<BlackScreenMarker> _markers = new();
    private readonly HashSet<string> _loggedErrors = new();

    private Thread? _thread;
    private ManualResetEventSlim? _stop;
    private EventLogCollector? _eventLogs;
    private SystemSnapshot? _lastTick;
    private SystemSnapshot? _lastFull;
    private DateTime _nextFull = DateTime.MinValue;
    private DateTime _nextEvents = DateTime.MinValue;
    private DateTime _nextStatusFile = DateTime.MinValue;
    private StreamWriter? _timelineWriter;
    private bool _systemEventsHooked;

    public MonitorEngine(AppSettings settings)
    {
        Settings = settings;
        settings.Normalize();
        _collector.Configure(settings);
        StartedUtc = DateTime.UtcNow;
    }

    public AppSettings Settings { get; }
    public DateTime StartedUtc { get; }
    public bool IsRunning => _thread != null;
    public bool IsElevated => SnapshotCollector.IsElevated;
    public static string Version => Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0.0";

    public SystemSnapshot? Live { get; private set; }
    public SystemSnapshot? Baseline { get; private set; }
    public SystemSnapshot? After { get; private set; }
    public DiagnosticVerdict? Verdict { get; private set; }
    public string? SessionFolder { get; private set; }

    /// <summary>Raised (on a background thread) after every monitoring tick or state change.</summary>
    public event Action? Updated;

    /// <summary>Diagnostic log lines for the UI / console.</summary>
    public event Action<string>? Log;

    public string ReportsFolder => Path.Combine(Settings.ReportFolder, "Reports");
    public string MarkRequestPath => Path.Combine(Settings.ReportFolder, "mark.request");
    public string StatusFilePath => Path.Combine(Settings.ReportFolder, "status.txt");

    public IReadOnlyList<TimelineEvent> GetTimeline() { lock (_gate) return _timeline.ToList(); }
    public IReadOnlyList<EventLogEntryInfo> GetEvents() { lock (_gate) return _events.ToList(); }
    public IReadOnlyList<BlackScreenMarker> GetMarkers() { lock (_gate) return _markers.ToList(); }

    // -------------------------------------------------------------------------------- lifecycle
    public void Start()
    {
        if (_thread != null) return;
        _collector.Configure(Settings);
        _stop = new ManualResetEventSlim(false);
        _eventLogs ??= new EventLogCollector(TimeSpan.FromMinutes(Settings.EventLookbackMinutes));
        _nextFull = DateTime.MinValue;
        _nextEvents = DateTime.MinValue;
        OpenSessionFolder();
        HookSystemEvents();
        AddTimeline(new TimelineEvent
        {
            TimeUtc = DateTime.UtcNow, Category = "Monitor", Severity = Severity.Info, Source = "User",
            Title = $"Monitoring started (interval {Settings.FastIntervalSeconds}s, {(IsElevated ? "administrator" : "standard user")})",
        });
        _thread = new Thread(Loop) { IsBackground = true, Name = "MeshScreenDiag monitor", Priority = ThreadPriority.BelowNormal };
        _thread.Start();
    }

    public void Stop()
    {
        var t = _thread;
        if (t == null) return;
        _stop?.Set();
        t.Join(TimeSpan.FromSeconds(15));
        _thread = null;
        AddTimeline(new TimelineEvent { TimeUtc = DateTime.UtcNow, Category = "Monitor", Severity = Severity.Info, Source = "User", Title = "Monitoring stopped" });
        Updated?.Invoke();
    }

    public void Dispose()
    {
        Stop();
        UnhookSystemEvents();
        lock (_gate)
        {
            _timelineWriter?.Dispose();
            _timelineWriter = null;
        }
    }

    private void Loop()
    {
        while (!_stop!.IsSet)
        {
            var started = DateTime.UtcNow;
            try
            {
                Tick();
            }
            catch (Exception ex)
            {
                EmitLog("Monitoring tick failed: " + ex);
            }
            var wait = TimeSpan.FromSeconds(Settings.FastIntervalSeconds) - (DateTime.UtcNow - started);
            if (wait < TimeSpan.FromMilliseconds(250)) wait = TimeSpan.FromMilliseconds(250);
            _stop.Wait(wait);
        }
    }

    // -------------------------------------------------------------------------------- one tick
    private void Tick()
    {
        var now = DateTime.UtcNow;
        var full = now >= _nextFull;
        var snap = _collector.Collect(full, full ? "Full sample" : "Sample");
        if (full) _nextFull = now + TimeSpan.FromSeconds(Settings.FullIntervalSeconds);

        var newEvents = new List<TimelineEvent>();
        if (_lastTick != null)
            newEvents.AddRange(TimelineBuilder.FromDiff(SnapshotComparer.Compare(_lastTick, snap, SnapshotSections.Fast)));
        if (full && _lastFull != null)
            newEvents.AddRange(TimelineBuilder.FromDiff(SnapshotComparer.Compare(_lastFull, snap, SnapshotSections.Slow)));

        var prevCapture = _lastTick?.Capture;
        if (full) _lastFull = snap;
        _lastTick = snap;

        if (now >= _nextEvents && _eventLogs != null)
        {
            _nextEvents = now + TimeSpan.FromSeconds(Settings.EventLogIntervalSeconds);
            var errs = new List<string>();
            var entries = _eventLogs.Poll(IsElevated, errs);
            snap.CollectorErrors.AddRange(errs);
            lock (_gate)
            {
                foreach (var e in entries)
                {
                    if (!_eventKeys.Add(e.Key)) continue;
                    _events.Add(e);
                    newEvents.Add(TimelineBuilder.FromEventLog(e));
                }
                if (_events.Count > 20000) _events.RemoveRange(0, _events.Count - 20000);
            }
        }

        foreach (var e in newEvents) AddTimeline(e, raise: false);
        foreach (var err in snap.CollectorErrors) if (_loggedErrors.Add(err)) EmitLog(err);

        Live = SnapshotCollector.Merge(snap, _lastFull);

        // Black-screen auto-detection: capture was fine (or absent) and is now black / failing.
        var nowBlack = snap.Capture is { } c && (c.AnyBlack || c.Monitors.Any(m => !m.Succeeded));
        var wasBlack = prevCapture is { } pc && (pc.AnyBlack || pc.Monitors.Any(m => !m.Succeeded));
        if (nowBlack && !wasBlack && prevCapture != null && Settings.AutoMarkOnBlack)
            AddMarker("Capture test turned black: " + snap.Capture!.Summary, automatic: true);

        CheckMarkRequest();
        Analyze();
        WriteStatusFile();
        Updated?.Invoke();
    }

    public DiagnosticVerdict Analyze()
    {
        var live = Live;
        if (live == null) return Verdict ?? new DiagnosticVerdict();
        var v = AnalysisEngine.Analyze(new AnalysisInput
        {
            Current = live,
            Baseline = Baseline,
            Timeline = GetTimeline(),
            Markers = GetMarkers(),
            Events = GetEvents(),
            CorrelationWindow = TimeSpan.FromSeconds(Settings.CorrelationWindowSeconds),
        });
        Verdict = v;
        return v;
    }

    // -------------------------------------------------------------------------------- user actions
    /// <summary>Collects one full snapshot outside the loop (used when monitoring is not running).</summary>
    public SystemSnapshot RefreshNow()
    {
        var snap = _collector.Collect(true, "Manual refresh");
        if (_eventLogs == null)
        {
            _eventLogs = new EventLogCollector(TimeSpan.FromMinutes(Settings.EventLookbackMinutes));
            var entries = _eventLogs.Poll(IsElevated, snap.CollectorErrors);
            lock (_gate)
            {
                foreach (var e in entries.Where(e => _eventKeys.Add(e.Key)))
                {
                    _events.Add(e);
                    _timeline.Add(TimelineBuilder.FromEventLog(e));
                }
            }
        }
        _lastFull = snap;
        _lastTick ??= snap;
        Live = snap;
        Analyze();
        Updated?.Invoke();
        return snap;
    }

    public Task<SystemSnapshot> TakeBaselineAsync() => Task.Run(() =>
    {
        var snap = _collector.Collect(true, "Baseline (before the application)");
        Baseline = snap;
        After = null;
        _lastFull ??= snap;
        Live ??= snap;
        AddTimeline(new TimelineEvent
        {
            TimeUtc = snap.TimeUtc, Category = "Snapshot", Severity = Severity.Info, Source = "User",
            Title = $"Baseline snapshot taken ({snap.Processes.Count} processes, {snap.Connections.Count} endpoints, capture: {snap.Capture?.Summary})",
        });
        Analyze();
        Updated?.Invoke();
        return snap;
    });

    public Task<SystemSnapshot> TakeAfterAsync(string label = "After (application running)") => Task.Run(() =>
    {
        var snap = _collector.Collect(true, label);
        After = snap;
        var diff = Baseline != null ? SnapshotComparer.Compare(Baseline, snap) : null;
        AddTimeline(new TimelineEvent
        {
            TimeUtc = snap.TimeUtc, Category = "Snapshot", Severity = Severity.Info, Source = "User",
            Title = $"'{label}' snapshot taken" + (diff != null ? $": {diff.Items.Count} change(s) since baseline" : " (no baseline to compare with)"),
        });
        Analyze();
        Updated?.Invoke();
        return snap;
    });

    public void AddMarker(string note, bool automatic)
    {
        var m = new BlackScreenMarker { TimeUtc = DateTime.UtcNow, Note = note, Automatic = automatic };
        lock (_gate) _markers.Add(m);
        AddTimeline(new TimelineEvent
        {
            TimeUtc = m.TimeUtc, Category = "Marker", Severity = Severity.Critical, Source = automatic ? "Monitor" : "User",
            Title = (automatic ? "AUTO-DETECTED black screen" : "Technician marked: screen went BLACK") + (string.IsNullOrEmpty(note) ? "" : " — " + note),
        });
        EmitLog($"Black-screen marker added at {m.TimeUtc.ToLocalTime():HH:mm:ss}" + (automatic ? " (automatic)" : ""));

        // Capture the full system state at this moment and save a report so it can be fetched remotely.
        _ = Task.Run(async () =>
        {
            try
            {
                if (Baseline != null && (After == null || After.TimeUtc < m.TimeUtc))
                    await TakeAfterAsync(automatic ? "After (black screen auto-detected)" : "After (black screen marked)");
                else
                    Analyze();
                if (Settings.AutoSaveReportOnBlack)
                {
                    var paths = SaveReport();
                    EmitLog("Report saved: " + paths.Html);
                }
                Updated?.Invoke();
            }
            catch (Exception ex)
            {
                EmitLog("Could not complete black-screen snapshot/report: " + ex.Message);
            }
        });
    }

    /// <summary>Lets a technician place a marker from MeshCentral's terminal: <c>MeshScreenDiag.exe --mark</c> writes this file.</summary>
    private void CheckMarkRequest()
    {
        try
        {
            if (!File.Exists(MarkRequestPath)) return;
            var note = File.ReadAllText(MarkRequestPath).Trim();
            File.Delete(MarkRequestPath);
            AddMarker(string.IsNullOrEmpty(note) ? "requested from command line" : note, automatic: false);
        }
        catch (Exception ex)
        {
            EmitLog("Mark request file: " + ex.Message);
        }
    }

    // -------------------------------------------------------------------------------- reports
    public DiagnosticReport BuildReport(string? technicianNotes = null)
    {
        var live = Live ?? _collector.Collect(true, "Report");
        Live ??= live;
        var verdict = Analyze();
        var afterForDiff = After ?? live;
        return new DiagnosticReport
        {
            ToolVersion = Version,
            GeneratedUtc = DateTime.UtcNow,
            Verdict = verdict,
            Current = live,
            Baseline = Baseline,
            After = After,
            Diff = Baseline != null ? SnapshotComparer.Compare(Baseline, afterForDiff) : null,
            Timeline = GetTimeline().ToList(),
            Markers = GetMarkers().ToList(),
            Events = GetEvents().ToList(),
            TitlesRedacted = Settings.RedactWindowTitles,
            TechnicianNotes = technicianNotes,
            CorrelationWindow = TimeSpan.FromSeconds(Settings.CorrelationWindowSeconds),
        };
    }

    public ReportPaths SaveReport(string? technicianNotes = null, string? folder = null)
    {
        var report = BuildReport(technicianNotes);
        var dir = folder ?? ReportsFolder;
        try
        {
            Directory.CreateDirectory(dir);
        }
        catch
        {
            dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MeshScreenDiag", "Reports");
            Directory.CreateDirectory(dir);
        }
        var stem = Path.Combine(dir, $"ScreenDiag_{Sanitize(report.Current.MachineName)}_{report.GeneratedUtc.ToLocalTime():yyyyMMdd_HHmmss}");
        var html = stem + ".html";
        var json = stem + ".json";
        var txt = stem + ".txt";
        File.WriteAllText(html, new HtmlReportBuilder(report).Build(), Encoding.UTF8);
        var text = TextSummaryBuilder.Build(report);
        var jsonText = report.ToJson();
        if (report.TitlesRedacted)
        {
            // Redact the serialized text (titles also appear inside timeline/finding text); the live
            // snapshots stay unredacted for the local UI. The HTML builder redacts on its own.
            var titles = new[] { report.Current, report.Baseline, report.After }
                .Where(s => s != null).SelectMany(s => s!.Windows.Select(w => w.Title))
                .Where(t => t.Length >= 3).Distinct().OrderByDescending(t => t.Length);
            foreach (var t in titles)
            {
                text = text.Replace(t, "[redacted]", StringComparison.Ordinal);
                jsonText = jsonText.Replace(JsonEncodedText.Encode(t).ToString(), "[redacted]", StringComparison.Ordinal);
            }
        }
        File.WriteAllText(txt, text, Encoding.UTF8);
        File.WriteAllText(json, jsonText, Encoding.UTF8);
        AddTimeline(new TimelineEvent { TimeUtc = DateTime.UtcNow, Category = "Report", Severity = Severity.Info, Source = "User", Title = "Report saved: " + html });
        return new ReportPaths(html, json, txt);
    }

    private static string Sanitize(string s) => string.Concat(s.Select(ch => Path.GetInvalidFileNameChars().Contains(ch) ? '_' : ch));

    // -------------------------------------------------------------------------------- timeline
    private void AddTimeline(TimelineEvent e, bool raise = true)
    {
        lock (_gate)
        {
            _timeline.Add(e);
            if (_timeline.Count > MaxTimeline)
            {
                // Drop the oldest informational entries first.
                var idx = _timeline.FindIndex(x => x.Severity == Severity.Info);
                _timeline.RemoveAt(idx >= 0 ? idx : 0);
            }
            try
            {
                _timelineWriter?.WriteLine(JsonSerializer.Serialize(e, DiagnosticReport.JsonOptions).Replace("\r", "").Replace("\n", ""));
                _timelineWriter?.Flush();
            }
            catch
            {
                // Session log is best-effort.
            }
        }
        if (raise) Updated?.Invoke();
    }

    private void OpenSessionFolder()
    {
        if (SessionFolder != null) return;
        try
        {
            SessionFolder = Path.Combine(Settings.ReportFolder, "Sessions", DateTime.Now.ToString("yyyyMMdd_HHmmss"));
            Directory.CreateDirectory(SessionFolder);
            lock (_gate)
                _timelineWriter = new StreamWriter(Path.Combine(SessionFolder, "timeline.jsonl"), append: true, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            EmitLog("Could not create session folder: " + ex.Message);
            SessionFolder = null;
        }
    }

    private void WriteStatusFile()
    {
        if (DateTime.UtcNow < _nextStatusFile) return;
        _nextStatusFile = DateTime.UtcNow.AddSeconds(5);
        try
        {
            var live = Live;
            var v = Verdict;
            if (live == null || v == null) return;
            var sb = new StringBuilder();
            sb.AppendLine($"MeshScreenDiag live status — {DateTime.Now:yyyy-MM-dd HH:mm:ss} — {live.MachineName}");
            sb.AppendLine($"Verdict      : {v.Headline}");
            sb.AppendLine($"Conn/capture : {v.ConnectionVsCapture}");
            sb.AppendLine($"MeshAgent    : {live.Mesh?.Health} ({live.Mesh?.EstablishedCount} established, KVM {(live.Mesh?.KvmActive == true ? "running" : "not running")})");
            sb.AppendLine($"Capture test : {live.Capture?.Summary}");
            sb.AppendLine($"Input desktop: {(live.Display?.InputDesktopAccessible == false ? "SECURE DESKTOP (inaccessible)" : live.Display?.InputDesktopName)}");
            foreach (var w in live.Windows.Where(w => w.IsCaptureProtected))
                sb.AppendLine($"PROTECTED    : {w.ProcessName} (PID {w.Pid}) {w.AffinityDisplay}, {w.MaxMonitorCoverage:P0} of screen");
            sb.AppendLine($"Markers      : {GetMarkers().Count}; mark with: MeshScreenDiag.exe --mark \"note\"");
            Directory.CreateDirectory(Settings.ReportFolder);
            File.WriteAllText(StatusFilePath, sb.ToString());
        }
        catch
        {
            // Best-effort.
        }
    }

    // -------------------------------------------------------------------------------- Windows notifications
    private void HookSystemEvents()
    {
        if (_systemEventsHooked) return;
        try
        {
            SystemEvents.SessionSwitch += OnSessionSwitch;
            SystemEvents.DisplaySettingsChanged += OnDisplaySettingsChanged;
            SystemEvents.PowerModeChanged += OnPowerModeChanged;
            _systemEventsHooked = true;
        }
        catch (Exception ex)
        {
            EmitLog("Windows session/display notifications unavailable: " + ex.Message);
        }
    }

    private void UnhookSystemEvents()
    {
        if (!_systemEventsHooked) return;
        SystemEvents.SessionSwitch -= OnSessionSwitch;
        SystemEvents.DisplaySettingsChanged -= OnDisplaySettingsChanged;
        SystemEvents.PowerModeChanged -= OnPowerModeChanged;
        _systemEventsHooked = false;
    }

    private void OnSessionSwitch(object? sender, SessionSwitchEventArgs e)
    {
        var severity = e.Reason is SessionSwitchReason.SessionLock or SessionSwitchReason.ConsoleDisconnect or SessionSwitchReason.RemoteConnect
            or SessionSwitchReason.SessionLogoff ? Severity.High : Severity.Medium;
        AddTimeline(new TimelineEvent
        {
            TimeUtc = DateTime.UtcNow, Category = "Session", Severity = severity, Source = "Windows",
            Title = "Windows session event: " + e.Reason switch
            {
                SessionSwitchReason.ConsoleConnect => "console connected",
                SessionSwitchReason.ConsoleDisconnect => "console DISCONNECTED",
                SessionSwitchReason.RemoteConnect => "remote (RDP) session CONNECTED",
                SessionSwitchReason.RemoteDisconnect => "remote (RDP) session disconnected",
                SessionSwitchReason.SessionLogon => "user logged on",
                SessionSwitchReason.SessionLogoff => "user LOGGED OFF",
                SessionSwitchReason.SessionLock => "session LOCKED",
                SessionSwitchReason.SessionUnlock => "session unlocked",
                SessionSwitchReason.SessionRemoteControl => "session remote-control status changed",
                _ => e.Reason.ToString(),
            },
        });
    }

    private void OnDisplaySettingsChanged(object? sender, EventArgs e) =>
        AddTimeline(new TimelineEvent
        {
            TimeUtc = DateTime.UtcNow, Category = "Display", Severity = Severity.Medium, Source = "Windows",
            Title = "Display configuration changed (Windows notification: resolution, monitor or orientation change)",
        });

    private void OnPowerModeChanged(object? sender, PowerModeChangedEventArgs e) =>
        AddTimeline(new TimelineEvent
        {
            TimeUtc = DateTime.UtcNow, Category = "Session", Severity = e.Mode == PowerModes.Suspend ? Severity.High : Severity.Low, Source = "Windows",
            Title = "Power mode: " + e.Mode,
        });

    private void EmitLog(string line) => Log?.Invoke($"{DateTime.Now:HH:mm:ss} {line}");
}
