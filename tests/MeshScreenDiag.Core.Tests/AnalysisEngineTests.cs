using MeshScreenDiag.Core.Analysis;
using MeshScreenDiag.Core.Models;
using static MeshScreenDiag.Core.Tests.Fixtures;

namespace MeshScreenDiag.Core.Tests;

public class AnalysisEngineTests
{
    private static DiagnosticVerdict Analyze(SystemSnapshot current, SystemSnapshot? baseline = null,
        List<TimelineEvent>? timeline = null, List<BlackScreenMarker>? markers = null, List<EventLogEntryInfo>? events = null) =>
        AnalysisEngine.Analyze(new AnalysisInput
        {
            Current = current,
            Baseline = baseline,
            Timeline = timeline ?? new(),
            Markers = markers ?? new(),
            Events = events ?? new(),
        });

    [Fact]
    public void HealthySystem_ReportsNoCause_AndConnectionOk()
    {
        var v = Analyze(Healthy());

        Assert.Null(v.PrimaryCause);
        Assert.Equal("No problem detected right now", v.ConnectionVsCapture);
        Assert.Contains(v.Findings, f => f.Id == "mesh-ok");
    }

    [Fact]
    public void FullScreenWdaMonitorWindow_IsApplicationCaptureProtection_AndCaptureProblem()
    {
        var s = Healthy(T0.AddMinutes(5), "After");
        AddProtectedApp(s, 4242, "SecurePortal.exe", WindowInfo.WDA_MONITOR);
        MakeCaptureBlack(s);

        var v = Analyze(s, Healthy());

        Assert.Equal(CauseCategory.ApplicationCaptureProtection, v.PrimaryCause);
        Assert.Contains("SecurePortal.exe", v.Headline);
        Assert.StartsWith("CAPTURE", v.ConnectionVsCapture);
        var f = v.Findings.First(x => x.Category == CauseCategory.ApplicationCaptureProtection);
        Assert.Equal(Severity.Critical, f.Severity);
        Assert.Contains(f.Evidence, e => e.Contains("WDA_MONITOR"));
        // With a baseline and no marker, the new process is a suspect.
        Assert.Contains(v.SuspectApplications, x => x.Contains("SecurePortal.exe") && x.Contains("HAS CAPTURE-PROTECTED WINDOW"));
    }

    [Fact]
    public void ExcludeFromCaptureWindow_IsReportedWithLowerWeight()
    {
        var s = Healthy();
        AddProtectedApp(s, 4242, "Zoom.exe", WindowInfo.WDA_EXCLUDEFROMCAPTURE, coverage: 0.3);

        var v = Analyze(s);

        var f = v.Findings.Single(x => x.Id.StartsWith("wda-"));
        Assert.Equal(Severity.Medium, f.Severity);
        Assert.Contains("WDA_EXCLUDEFROMCAPTURE", f.Title);
        // The known-software rule must not double-report an app whose protected window was already found.
        Assert.DoesNotContain(v.Findings, x => x.Id == "known-Zoom");
    }

    [Fact]
    public void MinimizedProtectedWindow_IsIgnored()
    {
        var s = Healthy();
        AddProtectedApp(s, 4242, "Signal.exe", WindowInfo.WDA_MONITOR);
        s.Windows.Last().IsMinimized = true;

        var v = Analyze(s);

        Assert.DoesNotContain(v.Findings, x => x.Id.StartsWith("wda-"));
    }

    [Fact]
    public void SecureDesktop_WithUacPrompt_IsSecureDesktop()
    {
        var s = Healthy();
        s.Display!.InputDesktopAccessible = false;
        s.Display.InputDesktopName = null;
        s.Display.InputDesktopError = 5;
        s.Processes.Add(Proc(3000, "consent.exe", 1));
        s.Capture!.Monitors[0].Succeeded = false;
        s.Capture.Monitors[0].Win32Error = 5;

        var v = Analyze(s);

        Assert.Equal(CauseCategory.SecureDesktop, v.PrimaryCause);
        Assert.Contains("UAC", v.Headline);
        Assert.StartsWith("CAPTURE", v.ConnectionVsCapture);
    }

    [Fact]
    public void CustomDesktop_IsSecureDesktop()
    {
        var s = Healthy();
        s.Display!.InputDesktopName = "SafeExamBrowser_Desktop";
        s.Processes.Add(Proc(3100, "SafeExamBrowser.Client.exe", 1));

        var v = Analyze(s);

        Assert.Equal(CauseCategory.SecureDesktop, v.PrimaryCause);
        Assert.Contains(v.Findings, f => f.Id == "alt-desktop" && f.Title.Contains("SafeExamBrowser_Desktop"));
    }

    [Fact]
    public void DisconnectedAgent_IsConnectionProblem()
    {
        var s = Healthy();
        s.Mesh!.ServerConnected = false;
        s.Mesh.Connections.Clear();

        var v = Analyze(s);

        Assert.Equal("CONNECTION problem", v.ConnectionVsCapture);
        Assert.Contains(v.Findings, f => f.Id == "mesh-down" && f.Category == CauseCategory.FirewallNetwork);
    }

    [Fact]
    public void StoppedAgentService_IsMeshCentralAgentProblem()
    {
        var s = Healthy();
        s.Mesh!.ServiceState = "Stopped";
        s.Mesh.Processes.Clear();

        var v = Analyze(s);

        Assert.Equal(CauseCategory.MeshCentralAgent, v.PrimaryCause);
        Assert.Equal("CONNECTION problem", v.ConnectionVsCapture);
    }

    [Fact]
    public void ExclusiveFullScreenD3D_IsGpuDisplay()
    {
        var s = Healthy();
        AddProtectedApp(s, 5000, "Game.exe", WindowInfo.WDA_NONE);
        s.Processes.Last().ModuleIndicators = new() { "Direct3D 11" };
        s.Display!.NotificationState = DisplayState.QunsD3DFullScreen;
        MakeCaptureBlack(s);

        var v = Analyze(s);

        Assert.Equal(CauseCategory.GpuDisplay, v.PrimaryCause);
        Assert.Contains("exclusive full-screen", v.Headline);
    }

    [Fact]
    public void ProtectedMediaPath_IsProtectedContent()
    {
        var s = Healthy();
        AddProtectedApp(s, 6000, "msedge.exe", WindowInfo.WDA_NONE);
        s.Processes.Last().ModuleIndicators = new() { "PlayReady DRM", "Direct3D 11" };
        s.Processes.Add(Proc(6001, "mfpmp.exe", 1));

        var v = Analyze(s);

        Assert.Equal(CauseCategory.ProtectedContent, v.PrimaryCause);
    }

    [Fact]
    public void RdpSession_IsSessionState()
    {
        var s = Healthy();
        s.Display!.IsRemoteSession = true;
        s.Display.OwnSessionId = 2;
        s.Display.ActiveConsoleSessionId = 1;

        var v = Analyze(s);

        Assert.Equal(CauseCategory.SessionState, v.PrimaryCause);
    }

    [Fact]
    public void BlackCaptureWithoutAnyMechanism_FallsBackToGpuDisplay()
    {
        var s = Healthy();
        MakeCaptureBlack(s);

        var v = Analyze(s);

        Assert.Equal(CauseCategory.GpuDisplay, v.PrimaryCause);
        Assert.Contains(v.Findings, f => f.Id == "capture-black" && f.Severity == Severity.Critical);
        Assert.StartsWith("CAPTURE", v.ConnectionVsCapture);
    }

    [Fact]
    public void MarkerWhileLocalCaptureOk_PointsAtMeshAgentKvm()
    {
        var s = Healthy(T0.AddMinutes(3));
        var markers = new List<BlackScreenMarker> { new() { TimeUtc = T0.AddMinutes(3) } };

        var v = Analyze(s, markers: markers);

        Assert.Contains(v.Findings, f => f.Id == "capture-ok-but-black" && f.Category == CauseCategory.MeshCentralAgent);
        Assert.StartsWith("MESHAGENT KVM", v.ConnectionVsCapture);
    }

    [Fact]
    public void ProcessesStartedNearMarker_AreSuspects_NoiseIsFiltered()
    {
        var s = Healthy(T0.AddMinutes(3));
        AddProtectedApp(s, 4242, "BankClient.exe", WindowInfo.WDA_MONITOR);
        var marker = T0.AddMinutes(3);
        var timeline = new List<TimelineEvent>
        {
            new() { TimeUtc = marker.AddSeconds(-4), Category = "Process", Change = DiffChange.Added, Pid = 4242, ProcessName = "BankClient.exe", Title = "Started: BankClient.exe" },
            new() { TimeUtc = marker.AddSeconds(-3), Category = "Process", Change = DiffChange.Added, Pid = 777, ProcessName = "svchost.exe", Title = "Started: svchost.exe" },
            new() { TimeUtc = marker.AddMinutes(-30), Category = "Process", Change = DiffChange.Added, Pid = 888, ProcessName = "notepad.exe", Title = "Started: notepad.exe" },
        };

        var v = Analyze(s, timeline: timeline, markers: new() { new() { TimeUtc = marker } });

        Assert.Single(v.SuspectApplications);
        Assert.Contains("BankClient.exe", v.SuspectApplications[0]);
        Assert.Contains("-4s", v.SuspectApplications[0]);
    }

    [Fact]
    public void DefenderDetectionOfMeshAgent_IsCriticalSecuritySoftware()
    {
        var s = Healthy();
        var events = new List<EventLogEntryInfo>
        {
            new() { TimeUtc = T0, Channel = "Microsoft-Windows-Windows Defender/Operational", Provider = "Microsoft-Windows-Windows Defender", EventId = 1116, Level = "Warning", Message = "Microsoft Defender Antivirus has detected potentially unwanted software. Name: RemoteAccess:Win32/MeshAgent Path: file:_C:\\Program Files\\Mesh Agent\\MeshAgent.exe" },
        };

        var v = Analyze(s, events: events);

        Assert.Equal(CauseCategory.SecuritySoftware, v.PrimaryCause);
        Assert.Contains(v.Findings, f => f.Id == "av-mesh" && f.Severity == Severity.Critical);
    }

    [Fact]
    public void FirewallBlockRuleForAgent_IsFirewallNetwork()
    {
        var s = Healthy();
        s.Firewall!.Rules.Add(new FirewallRuleInfo { Name = "Block remote tools", Enabled = true, Direction = "Out", Action = "Block", Protocol = "Any", Application = @"C:\Program Files\Mesh Agent\MeshAgent.exe", Profiles = "All" });

        var v = Analyze(s);

        Assert.Equal(CauseCategory.FirewallNetwork, v.PrimaryCause);
    }

    [Fact]
    public void KvmRestartNearMarker_IsMeshCentralAgent()
    {
        var s = Healthy(T0.AddMinutes(2));
        var marker = T0.AddMinutes(2);
        var timeline = new List<TimelineEvent>
        {
            new() { TimeUtc = marker.AddSeconds(-2), Category = "MeshAgent", Severity = Severity.High, Title = "MeshAgent KVM process RESTARTED (PID 1500 exited, replaced by PID 1600)" },
        };

        var v = Analyze(s, timeline: timeline, markers: new() { new() { TimeUtc = marker } });

        Assert.Contains(v.Findings, f => f.Id == "mesh-kvm");
        Assert.Equal(CauseCategory.MeshCentralAgent, v.PrimaryCause);
    }

    [Fact]
    public void GpuResetEventNearMarker_IsGpuDisplay()
    {
        var s = Healthy(T0.AddMinutes(2));
        var marker = T0.AddMinutes(2);
        var events = new List<EventLogEntryInfo>
        {
            new() { TimeUtc = marker.AddSeconds(-10), Channel = "System", Provider = "Display", EventId = 4101, Level = "Warning", Message = "Display driver nvlddmkm stopped responding and has successfully recovered." },
        };

        var v = Analyze(s, markers: new() { new() { TimeUtc = marker } }, events: events);

        Assert.Contains(v.Findings, f => f.Id == "gpu-events" && f.Severity == Severity.High);
        Assert.Equal(CauseCategory.GpuDisplay, v.PrimaryCause);
    }

    [Fact]
    public void KnownCaptureProtectionAppStartedAfterBaseline_IsHigh()
    {
        var baseline = Healthy();
        var s = Healthy(T0.AddMinutes(1), "After");
        s.Processes.Add(Proc(7000, "LockDownBrowser.exe", 1, start: T0.AddSeconds(30)));

        var v = Analyze(s, baseline);

        var f = v.Findings.Single(x => x.Id == "known-LockDownBrowser");
        Assert.Equal(Severity.High, f.Severity);
        Assert.Equal(CauseCategory.ApplicationCaptureProtection, f.Category);
    }

    [Fact]
    public void NotElevated_AddsLimitationFinding()
    {
        var s = Healthy();
        s.IsElevated = false;

        var v = Analyze(s);

        Assert.Contains(v.Findings, f => f.Id == "not-elevated");
    }

    [Fact]
    public void ProtectedWindowClosedAfterMarker_IsStillBlamed_NotTheKvm()
    {
        var s = Healthy(T0.AddMinutes(5));
        var marker = T0.AddMinutes(2);
        var timeline = new List<TimelineEvent>
        {
            new() { TimeUtc = marker.AddSeconds(-3), Category = "Window", Severity = Severity.Critical, Pid = 4242, ProcessName = "SecurePortal.exe", Change = DiffChange.Added,
                    Title = "Capture protection ON: 'Portal' (SecurePortal.exe #4242) affinity WDA_MONITOR (renders black in captures), covers 100% of a monitor" },
        };

        var v = Analyze(s, timeline: timeline, markers: new() { new() { TimeUtc = marker } });

        Assert.Equal(CauseCategory.ApplicationCaptureProtection, v.PrimaryCause);
        Assert.Contains(v.Findings, f => f.Id == "wda-history-4242");
        Assert.DoesNotContain(v.Findings, f => f.Id == "capture-ok-but-black");
    }
}
