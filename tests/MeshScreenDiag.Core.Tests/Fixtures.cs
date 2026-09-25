using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Core.Tests;

/// <summary>Builders for realistic snapshots used across the tests.</summary>
internal static class Fixtures
{
    public static readonly DateTime T0 = new(2026, 9, 25, 10, 0, 0, DateTimeKind.Utc);
    public static readonly RectI Screen = new(0, 0, 1920, 1080);

    public static SystemSnapshot Healthy(DateTime? time = null, string label = "Baseline")
    {
        var t = time ?? T0;
        return new SystemSnapshot
        {
            Label = label,
            TimeUtc = t,
            MachineName = "CLIENT-PC",
            UserName = "CONTOSO\\alice",
            OsVersion = "Windows 11 Pro 24H2",
            IsElevated = true,
            OwnSessionId = 1,
            Processes = new()
            {
                Proc(4, "System", 0),
                Proc(900, "MeshAgent.exe", 0, @"C:\Program Files\Mesh Agent\MeshAgent.exe"),
                Proc(1200, "explorer.exe", 1, @"C:\Windows\explorer.exe"),
                Proc(1500, "MeshAgent.exe", 1, @"C:\Program Files\Mesh Agent\MeshAgent.exe", parent: 900),
            },
            Windows = new()
            {
                new WindowInfo { Handle = 0x10010, Pid = 1200, ProcessName = "explorer.exe", Title = "Documents", ClassName = "CabinetWClass", Bounds = new RectI(100, 100, 900, 700), MaxMonitorCoverage = 0.23, MonitorDevice = @"\\.\DISPLAY1", IsForeground = true },
            },
            Display = new DisplayState
            {
                Monitors = new() { new MonitorInfo { DeviceName = @"\\.\DISPLAY1", Bounds = Screen, IsPrimary = true, BitsPerPixel = 32, RefreshRateHz = 60 } },
                Adapters = new() { new GpuAdapterInfo { Name = "Intel(R) UHD Graphics 770", Vendor = "Intel Corporation", DriverVersion = "31.0.101.5186", Status = "OK", PnpDeviceId = "PCI\\VEN_8086" } },
                InputDesktopName = "Default",
                OwnDesktopName = "Default",
                NotificationState = "QUNS_ACCEPTS_NOTIFICATIONS",
                ActiveConsoleSessionId = 1,
                OwnSessionId = 1,
                OwnSessionConnectState = "Active",
                SessionLocked = false,
            },
            Capture = new CaptureTestResult
            {
                TimeUtc = t,
                Monitors = new() { new CaptureRegionResult { Name = @"\\.\DISPLAY1 (primary)", Bounds = Screen, Succeeded = true, BlackRatio = 0.05, MeanLuminance = 120, DistinctColors = 900 } },
            },
            Mesh = ConnectedMesh(),
            Connections = MeshConnections(),
            LoadedDrivers = new() { new LoadedDriverInfo { Name = "ntoskrnl.exe" }, new LoadedDriverInfo { Name = "dxgkrnl.sys" } },
            Services = new()
            {
                new ServiceInfo { Name = "Mesh Agent", DisplayName = "Mesh Agent", State = "Running", StartMode = "Auto", PathName = "\"C:\\Program Files\\Mesh Agent\\MeshAgent.exe\"", ProcessId = 900 },
            },
            HasServices = true,
            Firewall = new FirewallState
            {
                Profiles = new() { new FirewallProfileInfo { Name = "Private", IsActive = true, Enabled = true, DefaultInboundAction = "Block", DefaultOutboundAction = "Allow" } },
                Rules = new() { new FirewallRuleInfo { Name = "Mesh Agent background service", Enabled = true, Direction = "In", Action = "Allow", Protocol = "TCP", Application = @"C:\Program Files\Mesh Agent\MeshAgent.exe", Profiles = "All" } },
            },
            HasFirewall = true,
            HasSecurityProducts = true,
            HasAdapters = true,
        };
    }

    public static ProcessInfo Proc(int pid, string name, int session, string? path = null, int parent = 4, DateTime? start = null) => new()
    {
        Pid = pid,
        Name = name,
        SessionId = session,
        Path = path,
        ParentPid = parent,
        StartTimeUtc = start ?? T0.AddHours(-1),
    };

    public static MeshAgentStatus ConnectedMesh() => new()
    {
        Found = true,
        ServiceName = "Mesh Agent",
        ServiceState = "Running",
        ServiceStartMode = "Auto",
        InstallPath = @"C:\Program Files\Mesh Agent",
        ServerUrl = "wss://mesh.example.com:443/agent.ashx",
        ServerHost = "mesh.example.com",
        ServerPort = 443,
        ServerAddresses = new() { "203.0.113.10" },
        ServerConnected = true,
        Processes = new()
        {
            new MeshAgentProcess { Pid = 900, Name = "MeshAgent.exe", SessionId = 0, Role = "Service" },
            new MeshAgentProcess { Pid = 1500, Name = "MeshAgent.exe", SessionId = 1, Role = "KVM", CommandLine = "MeshAgent.exe -kvm1" },
        },
        Connections = MeshConnections(),
    };

    public static List<NetConnection> MeshConnections() => new()
    {
        new NetConnection { Protocol = "TCP", LocalAddress = "192.168.1.20", LocalPort = 50123, RemoteAddress = "203.0.113.10", RemotePort = 443, State = "ESTABLISHED", Pid = 900, ProcessName = "MeshAgent.exe", IsMeshAgent = true },
    };

    /// <summary>Adds a full-screen window of a new process with the given display affinity.</summary>
    public static void AddProtectedApp(SystemSnapshot s, int pid, string name, uint affinity, double coverage = 1.0)
    {
        s.Processes.Add(Proc(pid, name, 1, $@"C:\Program Files\Vendor\{name}", start: s.TimeUtc.AddSeconds(-5)));
        foreach (var w in s.Windows) w.IsForeground = false;
        s.Windows.Add(new WindowInfo
        {
            Handle = 0x20020, Pid = pid, ProcessName = name, Title = "Secure Client Portal", ClassName = "Chrome_WidgetWin_1",
            Bounds = Screen, MaxMonitorCoverage = coverage, MonitorDevice = @"\\.\DISPLAY1", DisplayAffinity = affinity, IsForeground = true,
        });
    }

    public static void MakeCaptureBlack(SystemSnapshot s)
    {
        s.Capture!.Monitors[0].BlackRatio = 0.999;
        s.Capture.Monitors[0].MeanLuminance = 0.1;
        s.Capture.Monitors[0].DistinctColors = 1;
    }
}
