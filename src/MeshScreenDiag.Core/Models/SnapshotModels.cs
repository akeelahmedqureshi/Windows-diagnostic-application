using System.Text.Json.Serialization;

namespace MeshScreenDiag.Core.Models;

public sealed class RectI
{
    public int Left { get; set; }
    public int Top { get; set; }
    public int Right { get; set; }
    public int Bottom { get; set; }

    public RectI() { }

    public RectI(int left, int top, int right, int bottom)
    {
        Left = left;
        Top = top;
        Right = right;
        Bottom = bottom;
    }

    [JsonIgnore] public int Width => Math.Max(0, Right - Left);
    [JsonIgnore] public int Height => Math.Max(0, Bottom - Top);
    [JsonIgnore] public long Area => (long)Width * Height;

    public RectI Intersect(RectI other)
    {
        var l = Math.Max(Left, other.Left);
        var t = Math.Max(Top, other.Top);
        var r = Math.Min(Right, other.Right);
        var b = Math.Min(Bottom, other.Bottom);
        return r <= l || b <= t ? new RectI(0, 0, 0, 0) : new RectI(l, t, r, b);
    }

    /// <summary>Fraction (0..1) of <paramref name="container"/> covered by this rectangle.</summary>
    public double CoverageOf(RectI container) =>
        container.Area == 0 ? 0 : (double)Intersect(container).Area / container.Area;

    public override string ToString() => $"{Left},{Top} {Width}x{Height}";
}

public sealed class ProcessInfo
{
    public int Pid { get; set; }
    public int ParentPid { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public int SessionId { get; set; } = -1;
    public DateTime? StartTimeUtc { get; set; }
    public string? Company { get; set; }
    public string? Description { get; set; }
    public string? Signer { get; set; }
    public string? CommandLine { get; set; }
    public string? IntegrityLevel { get; set; }

    /// <summary>Loaded-module hints (e.g. "Direct3D 11", "PlayReady DRM"). Only filled for processes of interest.</summary>
    public List<string> ModuleIndicators { get; set; } = new();

    /// <summary>Stable identity across snapshots: PIDs are reused, so combine with the start time.</summary>
    [JsonIgnore]
    public string Key => $"{Pid}|{StartTimeUtc?.Ticks ?? 0}|{Name}";
}

public sealed class WindowInfo
{
    public long Handle { get; set; }
    public int Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string Title { get; set; } = "";
    public string ClassName { get; set; } = "";
    public RectI Bounds { get; set; } = new();

    /// <summary>Raw GetWindowDisplayAffinity value: 0 = none, 1 = WDA_MONITOR, 0x11 = WDA_EXCLUDEFROMCAPTURE.</summary>
    public uint DisplayAffinity { get; set; }

    public bool IsForeground { get; set; }
    public bool IsTopMost { get; set; }
    public bool IsLayered { get; set; }
    public bool IsClickThrough { get; set; }
    public bool IsCloaked { get; set; }
    public bool IsMinimized { get; set; }
    public bool IsHung { get; set; }

    /// <summary>Largest fraction of any single monitor covered by this window (0..1).</summary>
    public double MaxMonitorCoverage { get; set; }

    public string? MonitorDevice { get; set; }

    public const uint WDA_NONE = 0x0;
    public const uint WDA_MONITOR = 0x1;
    public const uint WDA_EXCLUDEFROMCAPTURE = 0x11;

    [JsonIgnore] public bool IsCaptureProtected => DisplayAffinity != WDA_NONE;
    [JsonIgnore] public bool IsFullScreen => MaxMonitorCoverage >= 0.98;

    public static string AffinityName(uint value) => value switch
    {
        WDA_NONE => "None",
        WDA_MONITOR => "WDA_MONITOR (renders black in captures)",
        WDA_EXCLUDEFROMCAPTURE => "WDA_EXCLUDEFROMCAPTURE (invisible in captures)",
        _ => $"0x{value:X}",
    };

    [JsonIgnore] public string AffinityDisplay => AffinityName(DisplayAffinity);
}

public sealed class ServiceInfo
{
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string State { get; set; } = "";
    public string StartMode { get; set; } = "";
    public string? PathName { get; set; }
    public int ProcessId { get; set; }
    /// <summary>"Service" or "Driver" (kernel / file-system driver registered with the SCM).</summary>
    public string Type { get; set; } = "Service";
}

/// <summary>A kernel module currently loaded (EnumDeviceDrivers).</summary>
public sealed class LoadedDriverInfo
{
    public string Name { get; set; } = "";
    public string? Path { get; set; }
}

public sealed class NetConnection
{
    public string Protocol { get; set; } = "TCP";
    public int IpVersion { get; set; } = 4;
    public string LocalAddress { get; set; } = "";
    public int LocalPort { get; set; }
    public string RemoteAddress { get; set; } = "";
    public int RemotePort { get; set; }
    public string State { get; set; } = "";
    public int Pid { get; set; }
    public string ProcessName { get; set; } = "";
    public string? ProcessPath { get; set; }
    public string Purpose { get; set; } = "";
    public bool IsMeshAgent { get; set; }

    [JsonIgnore]
    public string Key => $"{Protocol}{IpVersion}|{LocalAddress}:{LocalPort}|{RemoteAddress}:{RemotePort}|{Pid}";

    [JsonIgnore] public bool IsListening => State is "LISTEN" or "LISTENING" || (Protocol == "UDP");
    [JsonIgnore] public bool IsEstablished => State == "ESTABLISHED";

    public override string ToString() =>
        Protocol == "UDP"
            ? $"UDP {LocalAddress}:{LocalPort} ({ProcessName} #{Pid})"
            : $"TCP {LocalAddress}:{LocalPort} -> {RemoteAddress}:{RemotePort} {State} ({ProcessName} #{Pid})";
}

public sealed class FirewallProfileInfo
{
    public string Name { get; set; } = "";
    public bool IsActive { get; set; }
    public bool Enabled { get; set; }
    public string DefaultInboundAction { get; set; } = "";
    public string DefaultOutboundAction { get; set; } = "";
    public bool BlockAllInbound { get; set; }
}

public sealed class FirewallRuleInfo
{
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public string Direction { get; set; } = "";
    public string Action { get; set; } = "";
    public string Protocol { get; set; } = "";
    public string? LocalPorts { get; set; }
    public string? RemotePorts { get; set; }
    public string? RemoteAddresses { get; set; }
    public string? Application { get; set; }
    public string? Service { get; set; }
    public string Profiles { get; set; } = "";
    public string? Grouping { get; set; }

    /// <summary>Identity of a rule (names are not unique in Windows Firewall).</summary>
    [JsonIgnore]
    public string Key => $"{Name}|{Direction}|{Application}|{Service}|{Protocol}|{LocalPorts}|{RemotePorts}";

    [JsonIgnore]
    public string Fingerprint => $"{Enabled}|{Action}|{RemoteAddresses}|{Profiles}";

    public override string ToString() =>
        $"{Name} [{(Enabled ? "enabled" : "disabled")}, {Direction}, {Action}, {Protocol}" +
        (string.IsNullOrEmpty(LocalPorts) || LocalPorts == "*" ? "" : $", local {LocalPorts}") +
        (string.IsNullOrEmpty(RemotePorts) || RemotePorts == "*" ? "" : $", remote {RemotePorts}") +
        (string.IsNullOrEmpty(Application) ? "" : $", app {Application}") + "]";
}

public sealed class FirewallState
{
    public List<FirewallProfileInfo> Profiles { get; set; } = new();
    public List<FirewallRuleInfo> Rules { get; set; } = new();
    public string? Error { get; set; }
}

public sealed class SecurityProductInfo
{
    /// <summary>Antivirus, Firewall or Antispyware (Windows Security Center classes).</summary>
    public string Kind { get; set; } = "";
    public string Name { get; set; } = "";
    public uint ProductState { get; set; }
    public bool Enabled { get; set; }
    public bool UpToDate { get; set; }
    public string? ExecutablePath { get; set; }

    [JsonIgnore] public string Key => $"{Kind}|{Name}";

    /// <summary>
    /// Decodes the undocumented but well-known Security Center productState bitfield:
    /// byte 1 (0x00FF00) = 0x10/0x11 when enabled, byte 0 (0x0000FF) = 0x00 when signatures are current.
    /// </summary>
    public static (bool enabled, bool upToDate) DecodeProductState(uint state)
    {
        var scanner = (state >> 8) & 0xFF;
        var sigs = state & 0xFF;
        return ((scanner & 0x10) != 0, sigs == 0x00);
    }
}

public sealed class DefenderStatus
{
    public bool? AntivirusEnabled { get; set; }
    public bool? RealTimeProtectionEnabled { get; set; }
    public bool? BehaviorMonitorEnabled { get; set; }
    public bool? IsTamperProtected { get; set; }
    public string? ProductVersion { get; set; }
    public string? Error { get; set; }
}

public sealed class MonitorInfo
{
    public string DeviceName { get; set; } = "";
    public RectI Bounds { get; set; } = new();
    public bool IsPrimary { get; set; }
    public int BitsPerPixel { get; set; }
    public int RefreshRateHz { get; set; }
    public string? AdapterName { get; set; }

    public override string ToString() =>
        $"{DeviceName} {Bounds.Width}x{Bounds.Height}@{RefreshRateHz}Hz{(IsPrimary ? " (primary)" : "")}";
}

public sealed class GpuAdapterInfo
{
    public string Name { get; set; } = "";
    public string? DriverVersion { get; set; }
    public string? DriverDate { get; set; }
    public string? Status { get; set; }
    public string? Vendor { get; set; }
    public string? PnpDeviceId { get; set; }
    public string? CurrentMode { get; set; }
}

public sealed class DisplayState
{
    public List<MonitorInfo> Monitors { get; set; } = new();
    public List<GpuAdapterInfo> Adapters { get; set; } = new();

    /// <summary>Name of the desktop receiving input ("Default", "Winlogon", "Screen-saver", or custom).</summary>
    public string? InputDesktopName { get; set; }
    public bool InputDesktopAccessible { get; set; } = true;
    public int InputDesktopError { get; set; }
    /// <summary>Desktop this diagnostic process is attached to (normally "Default").</summary>
    public string? OwnDesktopName { get; set; }

    /// <summary>SHQueryUserNotificationState result, e.g. QUNS_RUNNING_D3D_FULL_SCREEN.</summary>
    public string NotificationState { get; set; } = "";

    public int ActiveConsoleSessionId { get; set; } = -1;
    public int OwnSessionId { get; set; } = -1;
    public string? OwnSessionConnectState { get; set; }
    public bool? SessionLocked { get; set; }
    public bool IsRemoteSession { get; set; }

    /// <summary>HKLM\SOFTWARE\Microsoft\Windows\Dwm\OverlayTestMode == 5 disables Multi-Plane Overlays.</summary>
    public bool? MpoDisabled { get; set; }
    /// <summary>Hardware-accelerated GPU scheduling (HwSchMode: 2 = on, 1 = off).</summary>
    public int? HagsMode { get; set; }

    public const string QunsD3DFullScreen = "QUNS_RUNNING_D3D_FULL_SCREEN";
    public const string QunsPresentation = "QUNS_PRESENTATION_MODE";
    public const string QunsBusy = "QUNS_BUSY";
    public const string QunsNotPresent = "QUNS_NOT_PRESENT";

    [JsonIgnore]
    public bool IsOnAlternateDesktop =>
        !InputDesktopAccessible ||
        (InputDesktopName != null && !InputDesktopName.Equals("Default", StringComparison.OrdinalIgnoreCase));

    [JsonIgnore]
    public string TopologyKey =>
        string.Join(";", Monitors.OrderBy(m => m.DeviceName)
            .Select(m => $"{m.DeviceName}:{m.Bounds}:{m.BitsPerPixel}:{m.RefreshRateHz}:{m.IsPrimary}"));
}

public sealed class CaptureRegionResult
{
    public string Name { get; set; } = "";
    public RectI Bounds { get; set; } = new();
    public bool Succeeded { get; set; }
    public int Win32Error { get; set; }
    /// <summary>Fraction of sampled pixels that are (near) black.</summary>
    public double BlackRatio { get; set; }
    public double MeanLuminance { get; set; }
    /// <summary>Approximate number of distinct colours in the sample (quantised).</summary>
    public int DistinctColors { get; set; }

    public const double BlackThreshold = 0.97;

    [JsonIgnore] public bool IsBlack => Succeeded && BlackRatio >= BlackThreshold;
    [JsonIgnore] public bool IsUniform => Succeeded && DistinctColors <= 2;

    [JsonIgnore]
    public string StatusText =>
        !Succeeded ? $"CAPTURE FAILED (Win32 error {Win32Error})"
        : IsBlack ? $"BLACK ({BlackRatio:P0} black pixels)"
        : IsUniform ? $"Uniform colour (luminance {MeanLuminance:F0})"
        : $"OK ({BlackRatio:P0} black, {DistinctColors} colours)";
}

public sealed class CaptureTestResult
{
    public DateTime TimeUtc { get; set; }
    public string Method { get; set; } = "GDI BitBlt from the desktop DC (same API family as the MeshAgent KVM)";
    public List<CaptureRegionResult> Monitors { get; set; } = new();
    /// <summary>Capture results for capture-protected windows only (window regions).</summary>
    public List<CaptureRegionResult> ProtectedWindows { get; set; } = new();
    public string? Error { get; set; }

    [JsonIgnore] public bool AnyBlack => Monitors.Any(m => m.IsBlack);
    [JsonIgnore] public bool AllBlack => Monitors.Count > 0 && Monitors.All(m => m.IsBlack);
    [JsonIgnore] public bool AnyFailed => Monitors.Any(m => !m.Succeeded) || Error != null;

    [JsonIgnore]
    public string Summary =>
        Error != null ? $"Capture error: {Error}"
        : Monitors.Count == 0 ? "Not tested"
        : AllBlack ? "ALL monitors capture as BLACK"
        : AnyBlack ? "Some monitors capture as BLACK"
        : AnyFailed ? "Capture FAILED on some monitors"
        : "Capture OK";
}

public sealed class MeshAgentProcess
{
    public int Pid { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public int SessionId { get; set; }
    /// <summary>"Service" (main agent), "KVM" (remote desktop child), or "Child".</summary>
    public string Role { get; set; } = "";
    public string? CommandLine { get; set; }
    public DateTime? StartTimeUtc { get; set; }
    public double? CpuPercent { get; set; }
    public double? IoBytesPerSec { get; set; }
}

public sealed class MeshAgentStatus
{
    public bool Found { get; set; }
    public List<MeshAgentProcess> Processes { get; set; } = new();
    public string? ServiceName { get; set; }
    public string? ServiceState { get; set; }
    public string? ServiceStartMode { get; set; }
    public string? InstallPath { get; set; }
    public string? ServerUrl { get; set; }
    public string? ServerHost { get; set; }
    public int? ServerPort { get; set; }
    public string? MeshName { get; set; }
    public List<string> ServerAddresses { get; set; } = new();
    public List<NetConnection> Connections { get; set; } = new();
    public List<string> Notes { get; set; } = new();

    [JsonIgnore] public int EstablishedCount => Connections.Count(c => c.Protocol == "TCP" && c.IsEstablished);

    /// <summary>At least one established TCP connection from an agent process to the server (or, if the
    /// server address is unknown, to any remote endpoint).</summary>
    public bool ServerConnected { get; set; }

    /// <summary>A KVM (remote desktop) child process exists, i.e. someone has the Desktop tab open.</summary>
    [JsonIgnore] public bool KvmActive => Processes.Any(p => p.Role == "KVM");

    [JsonIgnore]
    public string Health =>
        !Found ? "NOT FOUND"
        : ServiceState != null && !ServiceState.Equals("Running", StringComparison.OrdinalIgnoreCase) ? "SERVICE NOT RUNNING"
        : Processes.Count == 0 ? "NO AGENT PROCESS"
        : !ServerConnected ? "DISCONNECTED"
        : "CONNECTED";
}

public sealed class EventLogEntryInfo
{
    public DateTime TimeUtc { get; set; }
    public string Channel { get; set; } = "";
    public string Provider { get; set; } = "";
    public int EventId { get; set; }
    public string Level { get; set; } = "";
    public string Message { get; set; } = "";
    public long RecordId { get; set; }

    [JsonIgnore] public string Key => $"{Channel}|{RecordId}";
}

/// <summary>A full point-in-time picture of everything the tool collects.</summary>
public sealed class SystemSnapshot
{
    public string Label { get; set; } = "";
    public DateTime TimeUtc { get; set; }
    public string MachineName { get; set; } = "";
    public string UserName { get; set; } = "";
    public string OsVersion { get; set; } = "";
    public bool IsElevated { get; set; }
    public int OwnSessionId { get; set; }

    public List<ProcessInfo> Processes { get; set; } = new();
    public List<WindowInfo> Windows { get; set; } = new();
    public List<ServiceInfo> Services { get; set; } = new();
    public List<LoadedDriverInfo> LoadedDrivers { get; set; } = new();
    public List<NetConnection> Connections { get; set; } = new();
    public FirewallState? Firewall { get; set; }
    public List<SecurityProductInfo> SecurityProducts { get; set; } = new();
    public DefenderStatus? Defender { get; set; }
    public DisplayState? Display { get; set; }
    public CaptureTestResult? Capture { get; set; }
    public MeshAgentStatus? Mesh { get; set; }
    public List<EventLogEntryInfo> RecentEvents { get; set; } = new();

    /// <summary>Anything a collector could not read (access denied, API missing, ...).</summary>
    public List<string> CollectorErrors { get; set; } = new();

    /// <summary>Which sections were collected. Fast snapshots skip the expensive ones.</summary>
    public bool HasServices { get; set; }
    public bool HasFirewall { get; set; }
    public bool HasSecurityProducts { get; set; }
    public bool HasAdapters { get; set; }
}
