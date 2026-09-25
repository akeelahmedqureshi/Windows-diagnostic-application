using MeshScreenDiag.Core.Catalogs;
using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Core.Analysis;

public sealed class AnalysisInput
{
    public required SystemSnapshot Current { get; init; }
    public SystemSnapshot? Baseline { get; init; }
    public IReadOnlyList<TimelineEvent> Timeline { get; init; } = Array.Empty<TimelineEvent>();
    public IReadOnlyList<BlackScreenMarker> Markers { get; init; } = Array.Empty<BlackScreenMarker>();
    /// <summary>All event-log entries collected during the session (not only the ones in the current snapshot).</summary>
    public IReadOnlyList<EventLogEntryInfo> Events { get; init; } = Array.Empty<EventLogEntryInfo>();
    /// <summary>How far around the black-screen moment events are considered related.</summary>
    public TimeSpan CorrelationWindow { get; init; } = TimeSpan.FromMinutes(2);
}

/// <summary>
/// Rule-based root-cause analysis. Each rule looks at live state, the before/after difference and the
/// timeline around the black-screen moment, and emits findings with a weight towards one cause category.
/// The category with the highest total weight becomes the verdict.
/// </summary>
public static class AnalysisEngine
{
    /// <summary>Processes that start and stop all the time and are never the culprit.</summary>
    private static readonly HashSet<string> NoiseProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "conhost.exe", "backgroundTaskHost.exe", "RuntimeBroker.exe", "dllhost.exe",
        "SearchProtocolHost.exe", "SearchFilterHost.exe", "WmiPrvSE.exe", "taskhostw.exe", "smartscreen.exe",
        "WmiApSrv.exe", "audiodg.exe", "sppsvc.exe", "MpCmdRun.exe", "WerFault.exe", "wermgr.exe", "SgrmBroker.exe",
        "TiWorker.exe", "TrustedInstaller.exe", "MoUsoCoreWorker.exe", "UsoClient.exe", "CompatTelRunner.exe",
        "MeshScreenDiag.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "OpenConsole.exe", "sihost.exe",
        "SearchIndexer.exe", "ctfmon.exe", "fontdrvhost.exe",
        "MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe", "WUDFHost.exe", "upfc.exe", "DeviceCensus.exe",
    };

    public static DiagnosticVerdict Analyze(AnalysisInput input)
    {
        var ctx = new Ctx(input);
        var findings = new List<Finding>();

        RuleCaptureProtectedWindows(ctx, findings);
        RuleCaptureProtectionHistory(ctx, findings);
        RuleAlternateDesktop(ctx, findings);
        RuleSession(ctx, findings);
        RuleExclusiveFullScreen(ctx, findings);
        RuleProtectedContent(ctx, findings);
        RuleKnownSoftware(ctx, findings);
        RuleGpuEventsAndTopology(ctx, findings);
        RuleDisplayHardware(ctx, findings);
        RuleMeshAgent(ctx, findings);
        RuleSecurityEvents(ctx, findings);
        RuleFirewall(ctx, findings);
        RuleDriversAndServices(ctx, findings);
        RuleCaptureResult(ctx, findings);
        RuleEnvironment(ctx, findings);

        var suspects = FindSuspects(ctx);
        if (suspects.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "suspects",
                Category = CauseCategory.General,
                Severity = Severity.Info,
                Title = ctx.ReferenceTime != null
                    ? $"{suspects.Count} application(s) started around the black-screen moment"
                    : $"{suspects.Count} application(s) started after the baseline",
                Explanation = "These processes started close to when the screen went black (or since the baseline). The application that triggers the problem is almost always in this list.",
                Evidence = suspects,
                Recommendation = "Launch these one at a time with monitoring running to confirm which one blacks out the screen.",
            });
        }

        var scores = Enum.GetValues<CauseCategory>()
            .Where(c => c != CauseCategory.General)
            .Select(c => new CategoryScore
            {
                Category = c,
                Label = CategoryLabels.Of(c),
                Score = Math.Min(100, findings.Where(f => f.Category == c).Sum(f => f.Weight)),
            })
            .OrderByDescending(s => s.Score)
            .ToList();

        var verdict = new DiagnosticVerdict
        {
            TimeUtc = input.Current.TimeUtc,
            Findings = findings.OrderByDescending(f => f.Severity).ThenByDescending(f => f.Weight).ToList(),
            Scores = scores,
            SuspectApplications = suspects,
        };

        var top = scores.FirstOrDefault();
        if (top != null && top.Score >= 25)
        {
            verdict.PrimaryCause = top.Category;
            verdict.PrimaryCauseLabel = top.Label;
            var lead = findings.Where(f => f.Category == top.Category).OrderByDescending(f => f.Weight).First();
            verdict.Headline = $"Most likely cause: {top.Label} — {lead.Title}";
        }
        else if (ctx.Capture is { AnyBlack: true })
        {
            verdict.PrimaryCauseLabel = "Undetermined";
            verdict.Headline = "The screen captures as black, but no specific mechanism was identified yet. Take a baseline before launching the application and mark the moment the screen goes black.";
        }
        else
        {
            verdict.PrimaryCauseLabel = "None detected";
            verdict.Headline = "No blocking condition detected at the moment. Reproduce the problem while monitoring and press 'Screen went black NOW'.";
        }

        (verdict.ConnectionVsCapture, verdict.ConnectionVsCaptureDetail) = ConnectionVsCapture(ctx, findings);
        return verdict;
    }

    // ------------------------------------------------------------------------------------------
    private sealed class Ctx
    {
        public Ctx(AnalysisInput input)
        {
            Input = input;
            Current = input.Current;
            Display = input.Current.Display;
            Capture = input.Current.Capture;
            Mesh = input.Current.Mesh;
            ReferenceTime = input.Markers.Count > 0
                ? input.Markers.Max(m => m.TimeUtc)
                : input.Timeline.Where(e => e.Category == "Capture" && e.Severity >= Severity.High)
                    .Select(e => (DateTime?)e.TimeUtc).FirstOrDefault();
            Events = input.Events.Count > 0 ? input.Events : input.Current.RecentEvents;
        }

        public AnalysisInput Input { get; }
        public SystemSnapshot Current { get; }
        public DisplayState? Display { get; }
        public CaptureTestResult? Capture { get; }
        public MeshAgentStatus? Mesh { get; }
        public DateTime? ReferenceTime { get; }
        public IReadOnlyList<EventLogEntryInfo> Events { get; }

        /// <summary>True when <paramref name="t"/> is within the correlation window of the black-screen moment.</summary>
        public bool Near(DateTime t) =>
            ReferenceTime is { } r && t >= r - Input.CorrelationWindow && t <= r + TimeSpan.FromSeconds(30);

        /// <summary>Relevant if near the reference time, or (with no reference) anywhere after the baseline.</summary>
        public bool Relevant(DateTime t) =>
            ReferenceTime != null ? Near(t) : Input.Baseline != null && t >= Input.Baseline.TimeUtc;

        public IEnumerable<TimelineEvent> TimelineNear(string category) =>
            Input.Timeline.Where(e => e.Category == category && Relevant(e.TimeUtc));
    }

    // ------------------------------------------------------------------------------------------
    private static void RuleCaptureProtectedWindows(Ctx ctx, List<Finding> findings)
    {
        var windows = ctx.Current.Windows.Where(w => w.IsCaptureProtected && !w.IsMinimized && !w.IsCloaked).ToList();
        foreach (var w in windows.OrderByDescending(w => w.MaxMonitorCoverage))
        {
            var proc = ctx.Current.Processes.FirstOrDefault(p => p.Pid == w.Pid);
            var large = w.MaxMonitorCoverage >= 0.5;
            var isMonitor = w.DisplayAffinity == WindowInfo.WDA_MONITOR;
            var evidence = new List<string>
            {
                $"Window: '{w.Title}' (class {w.ClassName}, handle 0x{w.Handle:X})",
                $"Process: {w.ProcessName} (PID {w.Pid})" + (proc?.Path != null ? $" — {proc.Path}" : ""),
                $"GetWindowDisplayAffinity = {w.AffinityDisplay}",
                $"Covers {w.MaxMonitorCoverage:P0} of monitor {w.MonitorDevice}" + (w.IsFullScreen ? " (full screen)" : "") + (w.IsTopMost ? ", top-most" : ""),
            };
            if (proc?.Company != null) evidence.Add($"Publisher: {proc.Company}" + (proc.Signer != null ? $" (signed by {proc.Signer})" : ""));
            var wcap = ctx.Capture?.ProtectedWindows.FirstOrDefault(c => c.Name.EndsWith($"0x{w.Handle:X}", StringComparison.OrdinalIgnoreCase));
            if (wcap != null) evidence.Add($"Capture test of this window region: {wcap.StatusText}");
            var started = ctx.Input.Timeline.FirstOrDefault(e => e.Category == "Window" && e.Pid == w.Pid && e.Title.Contains("Capture protection ON"));
            if (started != null) evidence.Add($"Protection switched on at {started.TimeUtc.ToLocalTime():HH:mm:ss}");

            findings.Add(new Finding
            {
                Id = $"wda-{w.Handle:X}",
                Category = CauseCategory.ApplicationCaptureProtection,
                Severity = isMonitor ? (large ? Severity.Critical : Severity.High) : (large ? Severity.High : Severity.Medium),
                Weight = isMonitor ? (large ? 70 : 40) : (large ? 35 : 15),
                Title = isMonitor
                    ? $"{w.ProcessName} blocks screen capture of its window (WDA_MONITOR)"
                    : $"{w.ProcessName} hides its window from screen capture (WDA_EXCLUDEFROMCAPTURE)",
                Explanation = isMonitor
                    ? "The application called SetWindowDisplayAffinity(WDA_MONITOR). Windows (DWM) replaces the window's pixels with black in every capture API — GDI BitBlt, DXGI Desktop Duplication and Windows.Graphics.Capture — while the window stays fully visible on the physical monitor. The MeshAgent KVM captures the screen through these APIs, so the remote view is black exactly where this window is. Mouse and keyboard injection are unaffected, which is why the cursor still moves."
                    : "The application called SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE). The window is removed from every capture: the remote view shows whatever is behind it (often a black or empty desktop) while the local user sees the window.",
                Evidence = evidence,
                Recommendation = "This is enforced by the application, not by MeshCentral or Windows settings, and cannot be bypassed from the remote side. Check the application's own options/policy (e.g. 'screen capture protection', 'screen security', Citrix App Protection, Teams 'prevent screen capture', Horizon screen-capture blocking, banking/exam protection), ask the vendor or the client's administrator to allow capture for support sessions, or support that application by other means.",
            });
        }
    }

    /// <summary>Capture protection seen in the timeline around the black-screen moment, for windows that are gone now.</summary>
    private static void RuleCaptureProtectionHistory(Ctx ctx, List<Finding> findings)
    {
        var currentPids = ctx.Current.Windows.Where(w => w.IsCaptureProtected).Select(w => w.Pid).ToHashSet();
        var history = ctx.Input.Timeline
            .Where(e => e.Category == "Window" && e.Title.Contains("Capture protection ON") && e.Pid != null &&
                        !currentPids.Contains(e.Pid.Value) && ctx.Relevant(e.TimeUtc))
            .GroupBy(e => e.Pid!.Value)
            .ToList();
        foreach (var g in history)
        {
            var first = g.OrderBy(e => e.TimeUtc).First();
            var critical = g.Any(e => e.Severity >= Severity.Critical);
            findings.Add(new Finding
            {
                Id = $"wda-history-{g.Key}",
                Category = CauseCategory.ApplicationCaptureProtection,
                Severity = critical ? Severity.Critical : Severity.High,
                Weight = critical ? 60 : 35,
                Title = $"{first.ProcessName ?? "PID " + g.Key} turned on screen-capture protection around the black-screen moment (window closed since)",
                Explanation = "A window of this application had SetWindowDisplayAffinity capture protection while the screen was black. The window is no longer open, which is consistent with the remote view recovering after the application was closed.",
                Evidence = g.Select(e => $"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}").ToList(),
                Recommendation = "Re-open the application with monitoring running to confirm, then disable the protection in the application or its policy.",
            });
        }
    }

    private static void RuleAlternateDesktop(Ctx ctx, List<Finding> findings)
    {
        var d = ctx.Display;
        var consent = ctx.Current.Processes.Where(p => p.Name.Equals("consent.exe", StringComparison.OrdinalIgnoreCase)).ToList();
        var logonUi = ctx.Current.Processes.Where(p => p.Name.Equals("LogonUI.exe", StringComparison.OrdinalIgnoreCase)).ToList();
        var desktopEvents = ctx.TimelineNear("Desktop").ToList();

        if (d != null && d.IsOnAlternateDesktop)
        {
            var ev = new List<string>
            {
                d.InputDesktopAccessible
                    ? $"Input desktop is '{d.InputDesktopName}' (normal user desktop is 'Default')"
                    : $"The input desktop cannot be opened from the user session (Win32 error {d.InputDesktopError}) — this happens when the Winlogon/secure desktop (UAC prompt, lock screen, Ctrl+Alt+Del) or a protected custom desktop is active",
            };
            if (consent.Count > 0) ev.Add($"consent.exe (UAC prompt) is running: PID {string.Join(", ", consent.Select(p => p.Pid))}");
            if (logonUi.Count > 0) ev.Add($"LogonUI.exe is running: PID {string.Join(", ", logonUi.Select(p => p.Pid))} (sessions {string.Join(", ", logonUi.Select(p => p.SessionId))})");
            foreach (var e in desktopEvents) ev.Add($"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}");

            findings.Add(new Finding
            {
                Id = "alt-desktop",
                Category = CauseCategory.SecureDesktop,
                Severity = Severity.Critical,
                Weight = 70,
                Title = consent.Count > 0 ? "A UAC prompt is showing on the Secure Desktop"
                    : d.InputDesktopAccessible ? $"Input switched to a different desktop ('{d.InputDesktopName}')"
                    : "Input switched to the secure (Winlogon) desktop",
                Explanation = "Windows can run several desktops in one session, and only one receives input and is shown on screen. Screen capture only sees the desktop the capturing thread is attached to. When an application calls SwitchDesktop (Safe Exam Browser, Bitdefender Safepay, KeePass secure desktop, some banking/kiosk software) or Windows shows the UAC/lock screen, a capturer still attached to 'Default' gets a black or frozen image. Mouse injection can still work because the agent sends input at the system level.",
                Evidence = ev,
                Recommendation = consent.Count > 0
                    ? "Have the user answer the UAC prompt, or make sure the MeshCentral agent runs as a Windows service (SYSTEM) so its KVM can follow the secure desktop. Changing 'User Account Control: Switch to the secure desktop when prompting for elevation' is a security decision for the client."
                    : "Close the application that created the separate desktop (secure browser, password manager secure desktop, exam/kiosk software). MeshCentral cannot capture a private desktop created by another application.",
            });
        }
        else if (desktopEvents.Any(e => e.Severity >= Severity.High))
        {
            findings.Add(new Finding
            {
                Id = "alt-desktop-history",
                Category = CauseCategory.SecureDesktop,
                Severity = Severity.High,
                Weight = 45,
                Title = "The input desktop switched around the black-screen moment",
                Explanation = "The active desktop changed away from 'Default' near the time the screen went black. Capture tools attached to the default desktop see black while another desktop is active.",
                Evidence = desktopEvents.Select(e => $"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}").ToList(),
                Recommendation = "Identify the application that switched desktops (see suspects) and close it or change its secure-desktop option.",
            });
        }
    }

    private static void RuleSession(Ctx ctx, List<Finding> findings)
    {
        var d = ctx.Display;
        if (d == null) return;

        if (d.IsRemoteSession)
        {
            findings.Add(new Finding
            {
                Id = "rdp-session",
                Category = CauseCategory.SessionState,
                Severity = Severity.High,
                Weight = 45,
                Title = "The user is working in a Remote Desktop (RDP) session",
                Explanation = "This session is an RDP session, not the physical console. While a user is connected over RDP the console session is locked/disconnected. The MeshCentral KVM normally attaches to the console session, so it may show a black or login screen while the user works in RDP.",
                Evidence = new() { $"This process runs in session {d.OwnSessionId} (remote); active console session is {d.ActiveConsoleSessionId}" },
                Recommendation = "In MeshCentral, check which session the Desktop tab connects to, or have the user work at the console. Ending the RDP session returns the desktop to the console.",
            });
        }
        else if (d.ActiveConsoleSessionId >= 0 && d.OwnSessionId >= 0 && d.ActiveConsoleSessionId != d.OwnSessionId)
        {
            findings.Add(new Finding
            {
                Id = "session-mismatch",
                Category = CauseCategory.SessionState,
                Severity = Severity.High,
                Weight = 35,
                Title = "This user session is not the active console session",
                Explanation = "The physical console belongs to another session (fast user switching, disconnected session). MeshCentral shows the console session, which may be black, locked or belong to another user.",
                Evidence = new() { $"Own session {d.OwnSessionId} ({d.OwnSessionConnectState}); console session {d.ActiveConsoleSessionId}" },
                Recommendation = "Run this tool in the session the client is actually using, and select the matching session in MeshCentral.",
            });
        }

        if (d.NotificationState == DisplayState.QunsNotPresent && d.SessionLocked != true)
        {
            findings.Add(new Finding
            {
                Id = "not-present",
                Category = CauseCategory.SessionState,
                Severity = Severity.Medium,
                Weight = 25,
                Title = "Windows reports the user as 'not present'",
                Explanation = "SHQueryUserNotificationState returned QUNS_NOT_PRESENT: a screen saver is running, the machine is locked, or this is an inactive fast-user-switching session. The visible screen is then not the user's desktop.",
                Evidence = new() { "SHQueryUserNotificationState = QUNS_NOT_PRESENT" },
                Recommendation = "Wake the screen / unlock the session, and check screen-saver and fast-user-switching state.",
            });
        }

        if (d.SessionLocked == true)
        {
            findings.Add(new Finding
            {
                Id = "locked",
                Category = CauseCategory.SessionState,
                Severity = Severity.High,
                Weight = 30,
                Title = "The Windows session is locked",
                Explanation = "The lock screen runs on the Winlogon desktop. Capture from the user desktop is black until the session is unlocked.",
                Evidence = new() { "WTS session flags report the session as locked" },
                Recommendation = "Unlock the session. MeshCentral running as a service can normally show the lock screen; if it does not, check that the agent service runs as LocalSystem.",
            });
        }

        foreach (var e in ctx.TimelineNear("Session").Where(e => e.Severity >= Severity.High))
        {
            findings.Add(new Finding
            {
                Id = "session-event-" + e.TimeUtc.Ticks,
                Category = CauseCategory.SessionState,
                Severity = Severity.Medium,
                Weight = 20,
                Title = "Session change around the black-screen moment: " + e.Title,
                Explanation = "A lock, logoff, remote connect/disconnect or console switch happened near the time the screen went black.",
                Evidence = new() { $"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}" + (e.Details != null ? $" — {e.Details}" : "") },
                Recommendation = "Check whether the application launches a new session or requires RDP/console switching.",
            });
        }
    }

    private static void RuleExclusiveFullScreen(Ctx ctx, List<Finding> findings)
    {
        var d = ctx.Display;
        if (d == null) return;
        var fg = ctx.Current.Windows.FirstOrDefault(w => w.IsForeground);
        var fgProc = fg != null ? ctx.Current.Processes.FirstOrDefault(p => p.Pid == fg.Pid) : null;

        if (d.NotificationState == DisplayState.QunsD3DFullScreen)
        {
            var ev = new List<string> { "SHQueryUserNotificationState = QUNS_RUNNING_D3D_FULL_SCREEN" };
            if (fg != null) ev.Add($"Foreground: {fg.ProcessName} (PID {fg.Pid}) '{fg.Title}' covering {fg.MaxMonitorCoverage:P0}");
            if (fgProc?.ModuleIndicators.Count > 0) ev.Add("Rendering: " + string.Join(", ", fgProc.ModuleIndicators));
            findings.Add(new Finding
            {
                Id = "d3d-fullscreen",
                Category = CauseCategory.GpuDisplay,
                Severity = Severity.High,
                Weight = 50,
                Title = $"{fg?.ProcessName ?? "An application"} is running in exclusive full-screen Direct3D mode",
                Explanation = "In exclusive full-screen mode the application renders straight to the display, bypassing the desktop compositor. GDI-based capture (which the MeshAgent KVM uses) then returns black or a stale frame, while input keeps working.",
                Evidence = ev,
                Recommendation = "Switch the application to 'windowed' or 'borderless window' mode, or press Alt+Enter / Alt+Tab to leave exclusive full screen. Updating the GPU driver can also help.",
            });
        }
        else if (d.NotificationState == DisplayState.QunsPresentation)
        {
            findings.Add(new Finding
            {
                Id = "presentation",
                Category = CauseCategory.GpuDisplay,
                Severity = Severity.Low,
                Weight = 5,
                Title = "Presentation mode is active",
                Explanation = "An application put Windows into presentation mode (full-screen presentation or game).",
                Evidence = new() { "SHQueryUserNotificationState = QUNS_PRESENTATION_MODE" },
                Recommendation = "Informational.",
            });
        }

        foreach (var e in ctx.TimelineNear("Display").Where(e => e.Title.Contains(DisplayState.QunsD3DFullScreen)))
        {
            findings.Add(new Finding
            {
                Id = "d3d-history-" + e.TimeUtc.Ticks,
                Category = CauseCategory.GpuDisplay,
                Severity = Severity.High,
                Weight = 35,
                Title = "An exclusive full-screen Direct3D application started around the black-screen moment",
                Explanation = "Exclusive full-screen rendering bypasses the compositor and is typically captured as black.",
                Evidence = new() { $"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}" },
                Recommendation = "Run the application windowed / borderless.",
            });
            break;
        }
    }

    private static void RuleProtectedContent(Ctx ctx, List<Finding> findings)
    {
        var mfpmp = ctx.Current.Processes.Where(p => p.Name.Equals("mfpmp.exe", StringComparison.OrdinalIgnoreCase)).ToList();
        var drmProcs = ctx.Current.Processes.Where(p => p.ModuleIndicators.Any(KnownSoftwareCatalog.IsDrmIndicator)).ToList();
        if (mfpmp.Count == 0 && drmProcs.Count == 0) return;

        var ev = new List<string>();
        if (mfpmp.Count > 0) ev.Add($"mfpmp.exe (Protected Media Path) running: PID {string.Join(", ", mfpmp.Select(p => p.Pid))}");
        foreach (var p in drmProcs)
            ev.Add($"{p.Name} (PID {p.Pid}) has loaded: {string.Join(", ", p.ModuleIndicators.Where(KnownSoftwareCatalog.IsDrmIndicator))}");
        var fullScreenDrm = drmProcs.Any(p => ctx.Current.Windows.Any(w => w.Pid == p.Pid && w.MaxMonitorCoverage > 0.5 && !w.IsMinimized));

        findings.Add(new Finding
        {
            Id = "drm",
            Category = CauseCategory.ProtectedContent,
            Severity = fullScreenDrm || mfpmp.Count > 0 ? Severity.High : Severity.Medium,
            Weight = fullScreenDrm ? 45 : mfpmp.Count > 0 ? 35 : 15,
            Title = "Protected (DRM) media playback is active",
            Explanation = "DRM-protected video (PlayReady/Widevine hardware security, HDCP) is decoded and presented through a protected path. Capture APIs receive black instead of the protected surface, so the remote view shows a black rectangle (or a black screen for full-screen video) while the local monitor shows the video.",
            Evidence = ev,
            Recommendation = "Pause/close the protected video. For browsers, disabling hardware acceleration or 'PlayReady hardware DRM' removes the protected overlay (only if the client's policy allows it).",
        });
    }

    private static void RuleKnownSoftware(Ctx ctx, List<Finding> findings)
    {
        var hits = new Dictionary<string, (KnownSoftware sw, List<ProcessInfo> procs)>();
        foreach (var p in ctx.Current.Processes)
        {
            var k = KnownSoftwareCatalog.Match(p.Name);
            if (k == null || k.Kind is KnownSoftwareKind.WindowsState) continue;
            if (k.Pattern.Equals("mfpmp", StringComparison.OrdinalIgnoreCase)) continue; // covered by the DRM rule
            if (!hits.TryGetValue(k.Product, out var h)) hits[k.Product] = h = (k, new List<ProcessInfo>());
            h.procs.Add(p);
        }

        foreach (var (product, (sw, procs)) in hits)
        {
            var startedRecently = procs.Any(p =>
                ctx.Input.Timeline.Any(e => e.Category == "Process" && e.Change == DiffChange.Added && e.Pid == p.Pid && ctx.Relevant(e.TimeUtc)) ||
                (ctx.Input.Baseline != null && !ctx.Input.Baseline.Processes.Any(b => b.Key == p.Key)));
            var hasProtectedWindow = procs.Any(p => ctx.Current.Windows.Any(w => w.Pid == p.Pid && w.IsCaptureProtected));
            if (hasProtectedWindow) continue; // the WDA rule already reports it with harder evidence

            var cat = KnownSoftwareCatalog.CategoryOf(sw.Kind);
            int weight;
            Severity sev;
            switch (sw.Kind)
            {
                case KnownSoftwareKind.CaptureProtection:
                case KnownSoftwareKind.DesktopSwitch:
                case KnownSoftwareKind.ProtectedMedia:
                    (sev, weight) = startedRecently ? (Severity.High, 30) : (Severity.Medium, 12);
                    break;
                case KnownSoftwareKind.DataLossPrevention:
                    (sev, weight) = startedRecently ? (Severity.High, 25) : (Severity.Medium, 10);
                    break;
                case KnownSoftwareKind.RemoteAccess:
                case KnownSoftwareKind.VirtualDisplay:
                    (sev, weight) = startedRecently ? (Severity.Medium, 15) : (Severity.Low, 5);
                    break;
                default:
                    (sev, weight) = startedRecently ? (Severity.Medium, 10) : (Severity.Info, 0);
                    break;
            }

            findings.Add(new Finding
            {
                Id = "known-" + sw.Pattern,
                Category = cat,
                Severity = sev,
                Weight = weight,
                Title = $"{product} is running" + (startedRecently ? " (started around the black-screen moment)" : ""),
                Explanation = sw.Explanation,
                Evidence = procs.Select(p => $"{p.Name} PID {p.Pid}, session {p.SessionId}" + (p.Path != null ? $", {p.Path}" : "")).ToList(),
                Recommendation = sw.Kind switch
                {
                    KnownSoftwareKind.SecuritySuite => "Make sure the MeshCentral agent is allowed/excluded in this product and check its quarantine / event history for MeshAgent detections.",
                    KnownSoftwareKind.RemoteAccess => "Check whether this tool's privacy / black-screen mode or its display driver is active; close it while using MeshCentral.",
                    KnownSoftwareKind.VirtualDisplay => "Test capture with the virtual/USB display disconnected, or move the application to a monitor on the main GPU.",
                    _ => "Close the application or disable its capture-protection feature and re-test.",
                },
            });
        }
    }

    private static readonly string[] GpuProviders = { "display", "nvlddmkm", "amdkmdag", "amdkmdap", "amdwddmg", "igfx", "igfxn", "dxgkrnl", "microsoft-windows-dxgkrnl", "basicdisplay", "dwm", "desktop window manager" };

    private static void RuleGpuEventsAndTopology(Ctx ctx, List<Finding> findings)
    {
        var gpuEvents = ctx.Events.Where(e =>
                GpuProviders.Any(g => e.Provider.StartsWith(g, StringComparison.OrdinalIgnoreCase)) &&
                (e.Level is "Error" or "Warning" or "Critical" || e.EventId == 4101))
            .ToList();
        var near = gpuEvents.Where(e => ctx.Relevant(e.TimeUtc)).ToList();
        if (near.Count > 0 || gpuEvents.Count > 0)
        {
            var list = (near.Count > 0 ? near : gpuEvents).OrderByDescending(e => e.TimeUtc).Take(10).ToList();
            findings.Add(new Finding
            {
                Id = "gpu-events",
                Category = CauseCategory.GpuDisplay,
                Severity = near.Count > 0 ? Severity.High : Severity.Medium,
                Weight = near.Count > 0 ? 35 : 8,
                Title = near.Count > 0 ? "GPU / display driver errors around the black-screen moment" : "GPU / display driver errors in the event log",
                Explanation = "Display driver resets (TDR, event 4101), DWM crashes or GPU driver errors can make the capture surface black or stale until the capture is restarted.",
                Evidence = list.Select(e => $"{e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} {e.Provider} #{e.EventId} {e.Level}: {Trim(e.Message, 160)}").ToList(),
                Recommendation = "Update or roll back the GPU driver; disconnect and reconnect the MeshCentral Desktop tab after a reset.",
            });
        }

        var topo = ctx.TimelineNear("Display").Where(e => e.Title.Contains("configuration changed") || e.Title.Contains("adapter")).ToList();
        if (topo.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "topology",
                Category = CauseCategory.GpuDisplay,
                Severity = Severity.High,
                Weight = 35,
                Title = "Display configuration changed around the black-screen moment",
                Explanation = "The application changed resolution, refresh rate, the primary monitor or the set of monitors. The MeshAgent KVM may keep capturing the old display layout (black area) until the Desktop tab is reconnected, and some applications move themselves to a display the viewer is not showing.",
                Evidence = topo.Select(e => $"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}").ToList(),
                Recommendation = "Reconnect the MeshCentral Desktop tab, select the correct display in the viewer, and check the application's display/resolution settings.",
            });
        }
    }

    private static void RuleDisplayHardware(Ctx ctx, List<Finding> findings)
    {
        var d = ctx.Display;
        if (d == null) return;

        var virt = d.Adapters.Where(a => KnownSoftwareCatalog.IsVirtualAdapter(a.Name)).ToList();
        if (virt.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "virtual-adapter",
                Category = CauseCategory.GpuDisplay,
                Severity = Severity.Medium,
                Weight = 10,
                Title = "Virtual / indirect / USB display adapter present",
                Explanation = "Displays driven by indirect or USB display drivers (DisplayLink, virtual monitors from other remote tools, Basic Display Adapter) are sometimes captured as black, and applications opened on them are invisible to capture of the main display.",
                Evidence = virt.Select(a => $"{a.Name} (driver {a.DriverVersion}, status {a.Status})").ToList(),
                Recommendation = "Test with the application on a monitor attached to the main GPU; disable leftover virtual display drivers from other remote tools.",
            });
        }

        var physical = d.Adapters.Where(a => !KnownSoftwareCatalog.IsVirtualAdapter(a.Name)).ToList();
        var vendors = physical.Select(a => (a.Vendor ?? a.Name).Split(' ')[0].ToLowerInvariant()).Distinct().ToList();
        if (vendors.Count > 1)
        {
            findings.Add(new Finding
            {
                Id = "hybrid-gpu",
                Category = CauseCategory.GpuDisplay,
                Severity = Severity.Low,
                Weight = 8,
                Title = "Hybrid graphics (more than one GPU vendor)",
                Explanation = "On hybrid laptops (e.g. Intel + NVIDIA/AMD) an application rendered on the discrete GPU can be captured as black by some capture paths, especially with hardware-accelerated rendering.",
                Evidence = physical.Select(a => $"{a.Name} (driver {a.DriverVersion})").ToList(),
                Recommendation = "In Windows Graphics settings, set the application to 'Power saving' (integrated GPU) and re-test.",
            });
        }

        if (d.Monitors.Count > 1)
        {
            findings.Add(new Finding
            {
                Id = "multi-monitor",
                Category = CauseCategory.GpuDisplay,
                Severity = Severity.Info,
                Weight = 0,
                Title = $"{d.Monitors.Count} monitors connected",
                Explanation = "MeshCentral shows one display (or all) depending on the viewer setting. Make sure the viewer shows the display where the application runs.",
                Evidence = d.Monitors.Select(m => m.ToString()).ToList(),
                Recommendation = "Use the display selector in the MeshCentral Desktop tab.",
            });
        }
    }

    private static void RuleMeshAgent(Ctx ctx, List<Finding> findings)
    {
        var m = ctx.Mesh;
        if (m == null) return;

        if (!m.Found)
        {
            findings.Add(new Finding
            {
                Id = "mesh-missing",
                Category = CauseCategory.MeshCentralAgent,
                Severity = Severity.Critical,
                Weight = 40,
                Title = "MeshCentral agent not found",
                Explanation = "No MeshAgent service or process was found. If the agent uses a custom (branded) name, set it in Settings so it can be monitored.",
                Evidence = m.Notes.ToList(),
                Recommendation = "Set the agent process/service name in Settings, or reinstall the agent.",
            });
            return;
        }

        var ev = new List<string>
        {
            $"Service: {m.ServiceName ?? "(none)"} — {m.ServiceState ?? "unknown"} ({m.ServiceStartMode ?? "?"})",
            $"Server: {m.ServerUrl ?? "(unknown — .msh not readable)"}" + (m.ServerAddresses.Count > 0 ? $" resolves to {string.Join(", ", m.ServerAddresses)}" : ""),
            $"Established connections: {m.EstablishedCount}",
        };
        ev.AddRange(m.Processes.Select(p => $"{p.Role} process {p.Name} PID {p.Pid}, session {p.SessionId}" +
                                            (p.CpuPercent != null ? $", CPU {p.CpuPercent:F1}%" : "") +
                                            (p.IoBytesPerSec != null ? $", I/O {FormatRate(p.IoBytesPerSec.Value)}" : "")));

        if (m.Health != "CONNECTED")
        {
            findings.Add(new Finding
            {
                Id = "mesh-down",
                Category = m.Health == "DISCONNECTED" ? CauseCategory.FirewallNetwork : CauseCategory.MeshCentralAgent,
                Severity = Severity.Critical,
                Weight = 50,
                Title = $"MeshCentral agent is {m.Health}",
                Explanation = m.Health == "DISCONNECTED"
                    ? "The agent process is running but has no established connection to the MeshCentral server. This is a connection problem, not a capture problem."
                    : "The agent service or process is not running.",
                Evidence = ev,
                Recommendation = m.Health == "DISCONNECTED"
                    ? "Check firewall/proxy/security software for blocks on the agent (see Network and Security tabs) and the server reachability."
                    : "Start the 'Mesh Agent' service and check the Application/System event log for crashes.",
            });
        }

        var kvmEvents = ctx.Input.Timeline.Where(e => e.Category == "MeshAgent" && e.Severity >= Severity.High && ctx.Relevant(e.TimeUtc)).ToList();
        if (kvmEvents.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "mesh-kvm",
                Category = CauseCategory.MeshCentralAgent,
                Severity = Severity.High,
                Weight = 40,
                Title = "MeshAgent KVM / service process restarted or stopped around the black-screen moment",
                Explanation = "The agent runs remote desktop in a separate KVM process inside the user's session. If that process crashes or restarts, the viewer can freeze or go black while the main agent (and mouse relay) stays connected.",
                Evidence = kvmEvents.Select(e => $"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}").ToList(),
                Recommendation = "Check the Application log for MeshAgent crashes, update the agent, and reconnect the Desktop tab.",
            });
        }

        var crashes = ctx.Events.Where(e => e.Message.Contains("meshagent", StringComparison.OrdinalIgnoreCase) &&
                                            (e.Level is "Error" or "Critical" || e.EventId is 1000 or 1002 or 7031 or 7034)).ToList();
        if (crashes.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "mesh-crash",
                Category = CauseCategory.MeshCentralAgent,
                Severity = crashes.Any(e => ctx.Relevant(e.TimeUtc)) ? Severity.High : Severity.Medium,
                Weight = crashes.Any(e => ctx.Relevant(e.TimeUtc)) ? 45 : 15,
                Title = "MeshAgent errors/crashes in the event log",
                Explanation = "Windows recorded errors for the MeshAgent executable (application crash, hang or unexpected service termination).",
                Evidence = crashes.OrderByDescending(e => e.TimeUtc).Take(8).Select(e => $"{e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} {e.Provider} #{e.EventId}: {Trim(e.Message, 160)}").ToList(),
                Recommendation = "Update the MeshCentral agent and server; send the crash details to the MeshCentral project if it persists.",
            });
        }

        if (m.Health == "CONNECTED")
        {
            findings.Add(new Finding
            {
                Id = "mesh-ok",
                Category = CauseCategory.General,
                Severity = Severity.Info,
                Weight = 0,
                Title = "MeshCentral agent is connected to the server",
                Explanation = "The agent has an established connection to the server" + (m.KvmActive ? " and a KVM (remote desktop) process is running." : "; no KVM process is running right now (the Desktop tab is not open, or the KVM process exited)."),
                Evidence = ev,
                Recommendation = "Connection side looks healthy — focus on capture-side findings.",
            });
        }
    }

    private static void RuleSecurityEvents(Ctx ctx, List<Finding> findings)
    {
        var meshDetections = ctx.Events.Where(e =>
            e.Message.Contains("mesh", StringComparison.OrdinalIgnoreCase) &&
            (e.Channel.Contains("Defender", StringComparison.OrdinalIgnoreCase) ||
             e.Channel.Contains("AppLocker", StringComparison.OrdinalIgnoreCase) ||
             e.Channel.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase) ||
             e.Channel.Contains("SmartScreen", StringComparison.OrdinalIgnoreCase)))
            .ToList();
        if (meshDetections.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "av-mesh",
                Category = CauseCategory.SecuritySoftware,
                Severity = Severity.Critical,
                Weight = 60,
                Title = "Security software recorded events about the MeshCentral agent",
                Explanation = "Antivirus / application control logged detections or blocks that mention MeshAgent. Remote-access agents are often classified as 'RemoteAccess', 'HackTool' or PUA, and parts of the agent (such as the KVM) can be blocked or killed.",
                Evidence = meshDetections.OrderByDescending(e => e.TimeUtc).Take(10).Select(e => $"{e.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} {e.Channel} #{e.EventId}: {Trim(e.Message, 200)}").ToList(),
                Recommendation = "Allow/exclude the MeshAgent executable and folder in the security product (by signed hash or path) and restore it from quarantine if needed.",
            });
        }

        var defenderNear = ctx.Events.Where(e => e.Channel.Contains("Defender", StringComparison.OrdinalIgnoreCase) &&
                                                 e.EventId is 1006 or 1007 or 1008 or 1015 or 1116 or 1117 or 1118 or 1119 or 1121 or 1122 or 1125 or 1126 or 5001 or 5007 &&
                                                 ctx.Relevant(e.TimeUtc) && !meshDetections.Contains(e)).ToList();
        if (defenderNear.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "defender-near",
                Category = CauseCategory.SecuritySoftware,
                Severity = Severity.Medium,
                Weight = 15,
                Title = "Microsoft Defender activity around the black-screen moment",
                Explanation = "Defender detected, blocked or changed configuration near the time the screen went black.",
                Evidence = defenderNear.Take(10).Select(e => $"{e.TimeUtc.ToLocalTime():HH:mm:ss} #{e.EventId}: {Trim(e.Message, 200)}").ToList(),
                Recommendation = "Review the listed detections to see whether they involve the application or the agent.",
            });
        }

        if (ctx.Current.SecurityProducts.Count > 0 || ctx.Current.Defender != null)
        {
            var ev = ctx.Current.SecurityProducts.Select(p => $"{p.Kind}: {p.Name} — {(p.Enabled ? "enabled" : "disabled")}, {(p.UpToDate ? "up to date" : "out of date")}").ToList();
            if (ctx.Current.Defender is { } def)
                ev.Add($"Defender: AV {Fmt(def.AntivirusEnabled)}, real-time {Fmt(def.RealTimeProtectionEnabled)}, behaviour monitor {Fmt(def.BehaviorMonitorEnabled)}, tamper protection {Fmt(def.IsTamperProtected)}");
            findings.Add(new Finding
            {
                Id = "security-products",
                Category = CauseCategory.General,
                Severity = Severity.Info,
                Title = "Installed security products",
                Explanation = "Security products registered with Windows Security Center.",
                Evidence = ev,
                Recommendation = "Informational.",
            });
        }
    }

    private static void RuleFirewall(Ctx ctx, List<Finding> findings)
    {
        var fw = ctx.Current.Firewall;
        if (fw != null && fw.Error == null)
        {
            var meshBlocks = fw.Rules.Where(r => r.Enabled && r.Action.Equals("Block", StringComparison.OrdinalIgnoreCase) &&
                                                 (SnapshotComparer.IsMeshName(r.Application) || SnapshotComparer.IsMeshName(r.Name))).ToList();
            if (meshBlocks.Count > 0)
            {
                findings.Add(new Finding
                {
                    Id = "fw-mesh-block",
                    Category = CauseCategory.FirewallNetwork,
                    Severity = Severity.Critical,
                    Weight = 55,
                    Title = "Windows Firewall has BLOCK rules for the MeshCentral agent",
                    Explanation = "Enabled firewall rules block traffic for the agent executable.",
                    Evidence = meshBlocks.Select(r => r.ToString()).ToList(),
                    Recommendation = "Disable or remove these rules (or find which software/policy created them).",
                });
            }

            var outboundBlock = fw.Profiles.Where(p => p.IsActive && p.Enabled && p.DefaultOutboundAction.Equals("Block", StringComparison.OrdinalIgnoreCase)).ToList();
            if (outboundBlock.Count > 0)
            {
                var allow = fw.Rules.Any(r => r.Enabled && r.Direction == "Out" && r.Action == "Allow" && SnapshotComparer.IsMeshName(r.Application));
                findings.Add(new Finding
                {
                    Id = "fw-outbound-block",
                    Category = CauseCategory.FirewallNetwork,
                    Severity = allow ? Severity.Low : Severity.High,
                    Weight = allow ? 0 : (ctx.Mesh?.Health == "DISCONNECTED" ? 40 : 10),
                    Title = "Active firewall profile blocks outbound traffic by default" + (allow ? " (agent has an allow rule)" : ""),
                    Explanation = "With default-deny outbound, the agent needs an explicit outbound allow rule to reach the server.",
                    Evidence = outboundBlock.Select(p => $"Profile {p.Name}: outbound {p.DefaultOutboundAction}").ToList(),
                    Recommendation = allow ? "Informational." : "Add an outbound allow rule for the MeshAgent executable.",
                });
            }
        }

        var fwChanges = ctx.Input.Timeline.Where(e => e.Category is "FirewallRule" or "FirewallProfile" && ctx.Relevant(e.TimeUtc)).ToList();
        if (fwChanges.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "fw-changes",
                Category = CauseCategory.FirewallNetwork,
                Severity = fwChanges.Any(e => e.Severity >= Severity.High) ? Severity.High : Severity.Medium,
                Weight = fwChanges.Any(e => e.Severity >= Severity.High) ? 30 : 10,
                Title = $"{fwChanges.Count} firewall change(s) around the black-screen moment",
                Explanation = "Firewall rules or profiles changed when the application started. Some applications add block rules for remote-access tools.",
                Evidence = fwChanges.Take(15).Select(e => $"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}").ToList(),
                Recommendation = "Review the new/changed rules.",
            });
        }

        var drops = ctx.Events.Where(e => e.EventId is 5152 or 5157 && e.Message.Contains("mesh", StringComparison.OrdinalIgnoreCase)).ToList();
        if (drops.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "wfp-drops",
                Category = CauseCategory.FirewallNetwork,
                Severity = Severity.High,
                Weight = 45,
                Title = "Windows Filtering Platform dropped MeshAgent traffic",
                Explanation = "Security audit events 5152/5157 show packets or connections of the agent being blocked.",
                Evidence = drops.OrderByDescending(e => e.TimeUtc).Take(10).Select(e => $"{e.TimeUtc.ToLocalTime():HH:mm:ss} #{e.EventId}: {Trim(e.Message, 200)}").ToList(),
                Recommendation = "Find the filter that blocks the traffic (netsh wfp show filters) — often a third-party firewall or EDR.",
            });
        }
    }

    private static void RuleDriversAndServices(Ctx ctx, List<Finding> findings)
    {
        var drivers = ctx.Input.Timeline.Where(e => e.Category == "Driver" && e.Change == DiffChange.Added && ctx.Relevant(e.TimeUtc)).ToList();
        if (drivers.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "drivers-loaded",
                Category = CauseCategory.SecuritySoftware,
                Severity = Severity.Medium,
                Weight = 15,
                Title = $"{drivers.Count} kernel driver(s) loaded around the black-screen moment",
                Explanation = "Some protection products load a kernel driver when a protected application starts (anti-screenshot, anti-cheat, DLP, banking protection).",
                Evidence = drivers.Select(e => $"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}").ToList(),
                Recommendation = "Look up the driver's publisher (Drivers tab) to identify the product.",
            });
        }

        var services = ctx.Input.Timeline.Where(e => e.Category is "Service" && ctx.Relevant(e.TimeUtc) && e.Severity >= Severity.Low).ToList();
        if (services.Count > 0)
        {
            findings.Add(new Finding
            {
                Id = "services-changed",
                Category = CauseCategory.General,
                Severity = Severity.Low,
                Weight = 0,
                Title = $"{services.Count} service change(s) around the black-screen moment",
                Explanation = "Services that started, stopped or were installed near the time the screen went black.",
                Evidence = services.Take(15).Select(e => $"{e.TimeUtc.ToLocalTime():HH:mm:ss} {e.Title}").ToList(),
                Recommendation = "Informational.",
            });
        }
    }

    private static void RuleCaptureResult(Ctx ctx, List<Finding> findings)
    {
        var cap = ctx.Capture;
        if (cap == null) return;

        if (cap.Monitors.Any(m => !m.Succeeded))
        {
            var failed = cap.Monitors.Where(m => !m.Succeeded).ToList();
            findings.Add(new Finding
            {
                Id = "capture-failed",
                Category = CauseCategory.SecureDesktop,
                Severity = Severity.High,
                Weight = 25,
                Title = "Screen capture API call failed",
                Explanation = "BitBlt from the desktop failed. This happens when the input desktop is not accessible (secure desktop, lock screen, another desktop) or the session is disconnected.",
                Evidence = failed.Select(m => $"{m.Name}: {m.StatusText}").ToList(),
                Recommendation = "See the desktop/session findings.",
            });
        }

        if (cap.AnyBlack)
        {
            var explained = findings.Any(f => f.Weight >= 25 && f.Category != CauseCategory.General);
            findings.Add(new Finding
            {
                Id = "capture-black",
                Category = explained ? CauseCategory.General : CauseCategory.GpuDisplay,
                Severity = Severity.Critical,
                Weight = explained ? 0 : 25,
                Title = cap.AllBlack ? "The whole screen captures as BLACK from the user's session" : "Part of the screen captures as BLACK from the user's session",
                Explanation = "This tool captured the screen with GDI BitBlt (the same mechanism the MeshAgent KVM uses) and the image is black, while the physical monitor is not. This reproduces what MeshCentral sees independently of the network — the problem is on the capture side." +
                              (explained ? "" : " No application protection, desktop switch or DRM was detected, which leaves exclusive full-screen rendering, hardware overlays, a GPU/driver issue or a protection driver as the likely mechanism."),
                Evidence = cap.Monitors.Select(m => $"{m.Name} {m.Bounds}: {m.StatusText}").ToList(),
                Recommendation = explained
                    ? "See the higher-ranked findings for the mechanism."
                    : "Try: run the application windowed; disable hardware acceleration in the application; update the GPU driver; disable Multi-Plane Overlay (OverlayTestMode=5) as a test; check the suspects list for protection software.",
            });
        }

        // The technician said "black" but the local capture was fine at that moment: the problem is on the MeshAgent side.
        if (ctx.Input.Markers.Count > 0 && !cap.AnyBlack && !cap.AnyFailed &&
            !ctx.Input.Timeline.Any(e => e.Category is "Capture" or "Window" or "Desktop" && ctx.Near(e.TimeUtc) && e.Severity >= Severity.High) &&
            !findings.Any(f => f.Weight >= 25 && f.Category != CauseCategory.MeshCentralAgent) &&
            !ctx.Current.Windows.Any(w => w.IsCaptureProtected) && ctx.Display is { IsOnAlternateDesktop: false })
        {
            findings.Add(new Finding
            {
                Id = "capture-ok-but-black",
                Category = CauseCategory.MeshCentralAgent,
                Severity = Severity.High,
                Weight = 30,
                Title = "Local capture works while MeshCentral shows black",
                Explanation = "When the black screen was marked, this tool could still capture a normal image from the user's session, and no capture protection was active. That points at the MeshAgent KVM side: it may be capturing a different session/desktop, its KVM process may be stalled, or the viewer/relay may not be receiving frames.",
                Evidence = cap.Monitors.Select(m => $"{m.Name}: {m.StatusText}").ToList(),
                Recommendation = "Reconnect the MeshCentral Desktop tab, check which display/session it shows, check KVM process CPU/I-O in the MeshCentral tab, and update the agent.",
            });
        }
    }

    private static void RuleEnvironment(Ctx ctx, List<Finding> findings)
    {
        if (!ctx.Current.IsElevated)
        {
            findings.Add(new Finding
            {
                Id = "not-elevated",
                Category = CauseCategory.General,
                Severity = Severity.Low,
                Title = "Running without administrator rights — some data is incomplete",
                Explanation = "Without elevation the Security event log, command lines and I/O of SYSTEM processes (including the MeshAgent service) and some firewall details cannot be read.",
                Evidence = new(),
                Recommendation = "Use 'Restart as Administrator' for a complete report.",
            });
        }

        if (ctx.Current.OwnSessionId == 0)
        {
            findings.Add(new Finding
            {
                Id = "session0",
                Category = CauseCategory.General,
                Severity = Severity.Medium,
                Title = "Running in session 0 (service / SYSTEM context)",
                Explanation = "This instance runs in the non-interactive services session, so window, desktop and capture checks do not reflect the user's screen. MeshCentral's Terminal runs as SYSTEM in session 0 by default.",
                Evidence = new(),
                Recommendation = "Start the tool in the user's session (log-in as the user or use MeshCentral 'Run as user' / have the client start it).",
            });
        }

        var fg = ctx.Current.Windows.FirstOrDefault(w => w.IsForeground);
        var fgProc = fg != null ? ctx.Current.Processes.FirstOrDefault(p => p.Pid == fg.Pid) : null;
        if (fgProc?.IntegrityLevel is "High" or "System")
        {
            findings.Add(new Finding
            {
                Id = "fg-elevated",
                Category = CauseCategory.General,
                Severity = Severity.Low,
                Title = $"Foreground application {fgProc.Name} runs elevated ({fgProc.IntegrityLevel} integrity)",
                Explanation = "Elevated windows do not affect screen capture, but if keyboard/mouse input into that window fails, User Interface Privilege Isolation is the reason (the input sender must run at the same or higher integrity).",
                Evidence = new() { $"{fgProc.Name} PID {fgProc.Pid}" },
                Recommendation = "Informational.",
            });
        }
    }

    // ------------------------------------------------------------------------------------------
    private static List<string> FindSuspects(Ctx ctx)
    {
        var started = new List<(DateTime t, int pid, string name)>();
        foreach (var e in ctx.Input.Timeline.Where(e => e.Category == "Process" && e.Change == DiffChange.Added && e.Pid != null && ctx.Relevant(e.TimeUtc)))
            started.Add((e.TimeUtc, e.Pid!.Value, e.ProcessName ?? "?"));

        if (ctx.Input.Baseline != null && ctx.ReferenceTime == null)
        {
            var baseKeys = ctx.Input.Baseline.Processes.Select(p => p.Key).ToHashSet();
            foreach (var p in ctx.Current.Processes.Where(p => !baseKeys.Contains(p.Key)))
                if (!started.Any(s => s.pid == p.Pid))
                    started.Add((p.StartTimeUtc ?? ctx.Current.TimeUtc, p.Pid, p.Name));
        }

        var result = new List<(int rank, string text)>();
        foreach (var (t, pid, name) in started.DistinctBy(s => s.pid))
        {
            if (NoiseProcesses.Contains(name) || name.Contains("meshagent", StringComparison.OrdinalIgnoreCase)) continue;
            var p = ctx.Current.Processes.FirstOrDefault(x => x.Pid == pid);
            var protectedWin = ctx.Current.Windows.Any(w => w.Pid == pid && w.IsCaptureProtected);
            var known = KnownSoftwareCatalog.Match(name);
            var rank = (protectedWin ? 100 : 0) + (known != null ? 50 : 0) + (p?.ModuleIndicators.Count > 0 ? 10 : 0) +
                       (ctx.Current.Windows.Any(w => w.Pid == pid && w.IsFullScreen) ? 20 : 0) + (p != null ? 5 : 0);
            var tags = new List<string>();
            if (protectedWin) tags.Add("HAS CAPTURE-PROTECTED WINDOW");
            if (known != null) tags.Add("known: " + known.Product);
            if (p?.ModuleIndicators.Count > 0) tags.Add(string.Join("/", p.ModuleIndicators));
            if (p == null) tags.Add("already exited");
            var rel = ctx.ReferenceTime is { } r ? $" ({(t - r).TotalSeconds:+0;-0}s)" : "";
            result.Add((rank, $"{t.ToLocalTime():HH:mm:ss}{rel} {name} (PID {pid})" +
                              (p?.Path != null ? $" — {p.Path}" : "") +
                              (p?.Company != null ? $" [{p.Company}]" : "") +
                              (tags.Count > 0 ? " — " + string.Join("; ", tags) : "")));
        }
        return result.OrderByDescending(r => r.rank).Select(r => r.text).Take(25).ToList();
    }

    private static (string, string) ConnectionVsCapture(Ctx ctx, List<Finding> findings)
    {
        var m = ctx.Mesh;
        if (m == null || !m.Found)
            return ("UNKNOWN — agent not detected",
                "The MeshCentral agent could not be found, so the connection side cannot be judged. Configure the agent name in Settings if it is branded.");

        if (m.Health != "CONNECTED")
            return ("CONNECTION problem",
                $"The agent is {m.Health}. Without a server connection there is no remote view at all; fix connectivity first (firewall, proxy, security software, server).");

        var captureSide = findings.Where(f => f.Weight >= 25 && f.Category is CauseCategory.ApplicationCaptureProtection or CauseCategory.SecureDesktop
            or CauseCategory.ProtectedContent or CauseCategory.GpuDisplay or CauseCategory.SessionState).ToList();
        var kvm = m.KvmActive ? $"KVM process running (PID {string.Join(", ", m.Processes.Where(p => p.Role == "KVM").Select(p => p.Pid))})" : "no KVM process at the moment";
        var basis = $"Agent is connected ({m.EstablishedCount} established connection(s) to the server), {kvm}.";

        if (captureSide.Count > 0 || ctx.Capture is { AnyBlack: true })
            return ("CAPTURE / VISIBILITY problem (connection is fine)",
                basis + " The screen image itself is being blocked or blanked before MeshCentral encodes it. Mouse control keeps working because input is injected with SendInput, which does not depend on screen capture. Cause: " +
                (captureSide.Count > 0 ? string.Join("; ", captureSide.OrderByDescending(f => f.Weight).Take(3).Select(f => f.Title)) : "black capture (see findings)."));

        if (findings.Any(f => f.Id == "capture-ok-but-black"))
            return ("MESHAGENT KVM side (connection and local capture are fine)",
                basis + " Local capture works, so the image is lost between the KVM capture and the viewer.");

        return ("No problem detected right now",
            basis + " The screen captures normally at this moment. Reproduce the black screen while monitoring runs.");
    }

    private static string Trim(string s, int max)
    {
        s = s.Replace('\r', ' ').Replace('\n', ' ');
        return s.Length <= max ? s : s[..max] + "…";
    }

    private static string Fmt(bool? b) => b == null ? "unknown" : b.Value ? "on" : "OFF";

    public static string FormatRate(double bytesPerSec) =>
        bytesPerSec >= 1024 * 1024 ? $"{bytesPerSec / 1024 / 1024:F1} MB/s"
        : bytesPerSec >= 1024 ? $"{bytesPerSec / 1024:F1} KB/s"
        : $"{bytesPerSec:F0} B/s";
}
