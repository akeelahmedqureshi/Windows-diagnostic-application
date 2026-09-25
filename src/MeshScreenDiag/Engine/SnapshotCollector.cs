using System.Security.Principal;
using MeshScreenDiag.Collectors;
using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Engine;

/// <summary>
/// Builds <see cref="SystemSnapshot"/>s. A "fast" snapshot (every monitoring tick) covers processes,
/// windows, desktop/session, capture test, network, loaded drivers and the MeshAgent. A "full" snapshot
/// adds services, firewall, security products and GPU adapters.
/// </summary>
internal sealed class SnapshotCollector
{
    private readonly ProcessCollector _processes = new();
    private readonly MeshAgentCollector _mesh = new();
    private readonly object _lock = new();
    private bool _serviceIdentityKnown;

    public static readonly bool IsElevated = CheckElevated();

    public void Configure(AppSettings settings) => _mesh.Configure(settings.AgentNames);

    public SystemSnapshot Collect(bool full, string label)
    {
        // Collections can be requested from the monitor loop and from UI buttons at the same time;
        // the collectors keep per-process caches, so serialize them.
        lock (_lock)
        {
            return CollectCore(full, label);
        }
    }

    private SystemSnapshot CollectCore(bool full, string label)
    {
        var errors = new List<string>();
        var snap = new SystemSnapshot
        {
            Label = label,
            TimeUtc = DateTime.UtcNow,
            MachineName = Environment.MachineName,
            UserName = $"{Environment.UserDomainName}\\{Environment.UserName}",
            OsVersion = OsDescription(),
            IsElevated = IsElevated,
            OwnSessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId,
        };

        // Services first on full snapshots: they identify the agent service for the MeshAgent collector.
        if (full || !_serviceIdentityKnown)
        {
            snap.Services = Safe(() => ServiceCollector.GetServicesAndDrivers(errors), errors, "services") ?? new();
            snap.HasServices = snap.Services.Count > 0;
            _mesh.UpdateServiceIdentity(snap.Services);
            _serviceIdentityKnown = true;
        }

        snap.Processes = Safe(() => _processes.Collect(enrichPublisher: full, errors), errors, "processes") ?? new();
        var byPid = snap.Processes.GroupBy(p => p.Pid).ToDictionary(g => g.Key, g => g.First());
        var names = byPid.ToDictionary(kv => kv.Key, kv => kv.Value.Name);

        snap.Display = Safe(() => DisplayCollector.GetState(includeAdapters: full, errors), errors, "display");
        snap.HasAdapters = full && snap.Display?.Adapters.Count > 0;
        var monitors = snap.Display?.Monitors ?? new List<MonitorInfo>();

        snap.Windows = Safe(() => WindowCollector.Collect(monitors, names), errors, "windows") ?? new();
        snap.Capture = Safe(() => CaptureTester.Run(monitors, snap.Windows), errors, "capture test");

        EnrichInterestingProcesses(snap, byPid);

        var agentPids = _mesh.FindAgentPids(snap.Processes);
        snap.Connections = Safe(() => NetworkCollector.Collect(byPid, agentPids, errors), errors, "network") ?? new();
        snap.Mesh = Safe(() => _mesh.Collect(snap.Processes, snap.Connections, agentPids, resolveDns: full), errors, "MeshAgent");
        snap.LoadedDrivers = Safe(() => ServiceCollector.GetLoadedDrivers(errors), errors, "drivers") ?? new();

        if (full)
        {
            snap.Firewall = Safe(FirewallCollector.Collect, errors, "firewall");
            snap.HasFirewall = snap.Firewall != null;
            snap.SecurityProducts = Safe(() => SecurityCollector.GetProducts(errors), errors, "security products") ?? new();
            snap.Defender = Safe(SecurityCollector.GetDefender, errors, "Defender");
            snap.HasSecurityProducts = true;
        }

        snap.CollectorErrors = errors;
        return snap;
    }

    /// <summary>
    /// Module scan + integrity level only for processes that matter (window owners covering a large part of
    /// a monitor, capture-protected windows, the foreground app, protected-media host, agent processes).
    /// </summary>
    private void EnrichInterestingProcesses(SystemSnapshot snap, Dictionary<int, ProcessInfo> byPid)
    {
        var pids = new HashSet<int>();
        foreach (var w in snap.Windows)
            if (w.IsCaptureProtected || w.IsForeground || (w.MaxMonitorCoverage >= 0.5 && !w.IsMinimized))
                pids.Add(w.Pid);
        foreach (var p in snap.Processes.Where(p => p.Name.Equals("mfpmp.exe", StringComparison.OrdinalIgnoreCase)))
            pids.Add(p.Pid);

        foreach (var pid in pids.Take(40))
        {
            if (!byPid.TryGetValue(pid, out var p)) continue;
            p.ModuleIndicators = _processes.GetModuleIndicators(p);
            p.IntegrityLevel = ProcessCollector.GetIntegrityLevel(pid);
        }
    }

    private static T? Safe<T>(Func<T> f, List<string> errors, string what)
    {
        try
        {
            return f();
        }
        catch (Exception ex)
        {
            errors.Add($"{what}: {ex.GetType().Name}: {ex.Message}");
            return default;
        }
    }

    /// <summary>Copies the slow sections of the last full snapshot into a fast snapshot, giving a complete "live" view.</summary>
    public static SystemSnapshot Merge(SystemSnapshot fast, SystemSnapshot? full)
    {
        if (full == null || ReferenceEquals(fast, full)) return fast;
        fast.Services = full.Services;
        fast.HasServices = full.HasServices;
        fast.Firewall = full.Firewall;
        fast.HasFirewall = full.HasFirewall;
        fast.SecurityProducts = full.SecurityProducts;
        fast.Defender = full.Defender;
        fast.HasSecurityProducts = full.HasSecurityProducts;
        if (fast.Display != null && full.Display != null && fast.Display.Adapters.Count == 0)
        {
            fast.Display.Adapters = full.Display.Adapters;
            fast.HasAdapters = full.HasAdapters;
        }
        // Publisher details are only computed on full snapshots; carry them over by PID.
        var byKey = full.Processes.GroupBy(p => p.Key).ToDictionary(g => g.Key, g => g.First());
        foreach (var p in fast.Processes)
        {
            if (p.Company == null && byKey.TryGetValue(p.Key, out var fp))
            {
                p.Company = fp.Company;
                p.Description = fp.Description;
                p.Signer = fp.Signer;
            }
        }
        fast.CollectorErrors = fast.CollectorErrors.Concat(full.CollectorErrors).Distinct().ToList();
        return fast;
    }

    private static bool CheckElevated()
    {
        try
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static string OsDescription()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var product = k?.GetValue("ProductName")?.ToString();
            var display = k?.GetValue("DisplayVersion")?.ToString();
            var build = k?.GetValue("CurrentBuild")?.ToString();
            var ubr = k?.GetValue("UBR")?.ToString();
            // Windows 11 still reports "Windows 10" in ProductName; the build number tells them apart.
            if (product != null && int.TryParse(build, out var b) && b >= 22000) product = product.Replace("Windows 10", "Windows 11");
            return $"{product} {display} (build {build}.{ubr})".Trim();
        }
        catch
        {
            return Environment.OSVersion.VersionString;
        }
    }
}
