using MeshScreenDiag.Core.Catalogs;
using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Core.Analysis;

/// <summary>
/// Compares two snapshots and lists every relevant change. Used both for the explicit
/// before/after comparison and, between consecutive monitoring ticks, to build the timeline.
/// Sections that were not collected in either snapshot are skipped (not reported as removed).
/// </summary>
[Flags]
public enum SnapshotSections
{
    None = 0,
    Processes = 1,
    Windows = 2,
    DesktopSession = 4,
    DisplayTopology = 8,
    Capture = 16,
    Mesh = 32,
    Connections = 64,
    Drivers = 128,
    DisplayAdapters = 256,
    Services = 512,
    Firewall = 1024,
    Security = 2048,

    /// <summary>Cheap sections collected on every monitoring tick.</summary>
    Fast = Processes | Windows | DesktopSession | DisplayTopology | Capture | Mesh | Connections | Drivers,
    /// <summary>Expensive sections collected on full snapshots only.</summary>
    Slow = DisplayAdapters | Services | Firewall | Security,
    All = Fast | Slow,
}

public static class SnapshotComparer
{
    public static SnapshotDiff Compare(SystemSnapshot before, SystemSnapshot after, SnapshotSections sections = SnapshotSections.All)
    {
        var diff = new SnapshotDiff
        {
            BeforeUtc = before.TimeUtc,
            AfterUtc = after.TimeUtc,
            BeforeLabel = before.Label,
            AfterLabel = after.Label,
        };
        var items = diff.Items;

        bool On(SnapshotSections s) => (sections & s) != 0;

        if (On(SnapshotSections.Processes)) CompareProcesses(before, after, items);
        if (On(SnapshotSections.Windows)) CompareWindows(before, after, items);
        if (On(SnapshotSections.DesktopSession)) CompareDesktopAndSession(before.Display, after.Display, items);
        CompareDisplay(before.Display, after.Display, items,
            topology: On(SnapshotSections.DisplayTopology),
            adapters: On(SnapshotSections.DisplayAdapters) && before.HasAdapters && after.HasAdapters);
        if (On(SnapshotSections.Capture)) CompareCapture(before.Capture, after.Capture, items);
        if (On(SnapshotSections.Mesh)) CompareMesh(before.Mesh, after.Mesh, items);
        if (On(SnapshotSections.Connections)) CompareConnections(before, after, items);
        if (On(SnapshotSections.Drivers)) CompareDrivers(before, after, items);
        if (On(SnapshotSections.Services) && before.HasServices && after.HasServices) CompareServices(before, after, items);
        if (On(SnapshotSections.Firewall) && before.HasFirewall && after.HasFirewall) CompareFirewall(before.Firewall, after.Firewall, items);
        if (On(SnapshotSections.Security) && before.HasSecurityProducts && after.HasSecurityProducts) CompareSecurity(before, after, items);

        return diff;
    }

    private static void CompareProcesses(SystemSnapshot a, SystemSnapshot b, List<DiffItem> items)
    {
        if (a.Processes.Count == 0 || b.Processes.Count == 0) return;
        var before = a.Processes.GroupBy(p => p.Key).ToDictionary(g => g.Key, g => g.First());
        var after = b.Processes.GroupBy(p => p.Key).ToDictionary(g => g.Key, g => g.First());

        foreach (var (key, p) in after)
        {
            if (before.ContainsKey(key)) continue;
            var known = KnownSoftwareCatalog.Match(p.Name);
            items.Add(new DiffItem
            {
                Area = "Process",
                Change = DiffChange.Added,
                Key = key,
                Pid = p.Pid,
                ProcessName = p.Name,
                Severity = known != null ? SeverityForKnown(known.Kind) : Severity.Info,
                Description = $"Started: {p.Name} (PID {p.Pid}, session {p.SessionId})" +
                              (p.Path != null ? $" {p.Path}" : "") +
                              (known != null ? $" — known: {known.Product}" : ""),
            });
        }

        foreach (var (key, p) in before)
        {
            if (after.ContainsKey(key)) continue;
            var known = KnownSoftwareCatalog.Match(p.Name);
            items.Add(new DiffItem
            {
                Area = "Process",
                Change = DiffChange.Removed,
                Key = key,
                Pid = p.Pid,
                ProcessName = p.Name,
                Severity = known != null && known.Kind != KnownSoftwareKind.WindowsState ? Severity.Low : Severity.Info,
                Description = $"Exited: {p.Name} (PID {p.Pid})" + (known != null ? $" — known: {known.Product}" : ""),
            });
        }
    }

    private static void CompareWindows(SystemSnapshot a, SystemSnapshot b, List<DiffItem> items)
    {
        var before = a.Windows.GroupBy(w => w.Handle).ToDictionary(g => g.Key, g => g.First());
        var after = b.Windows.GroupBy(w => w.Handle).ToDictionary(g => g.Key, g => g.First());

        foreach (var (h, w) in after)
        {
            before.TryGetValue(h, out var old);
            var oldAffinity = old?.DisplayAffinity ?? WindowInfo.WDA_NONE;
            if (w.DisplayAffinity != oldAffinity)
            {
                items.Add(new DiffItem
                {
                    Area = "Window",
                    Change = old == null ? DiffChange.Added : DiffChange.Changed,
                    Key = $"affinity|{h}",
                    Pid = w.Pid,
                    ProcessName = w.ProcessName,
                    Severity = w.DisplayAffinity == WindowInfo.WDA_MONITOR && w.MaxMonitorCoverage > 0.5 ? Severity.Critical
                        : w.DisplayAffinity != WindowInfo.WDA_NONE ? Severity.High : Severity.Medium,
                    Description = w.DisplayAffinity != WindowInfo.WDA_NONE
                        ? $"Capture protection ON: '{w.Title}' ({w.ProcessName} #{w.Pid}) affinity {w.AffinityDisplay}, covers {w.MaxMonitorCoverage:P0} of a monitor"
                        : $"Capture protection OFF: '{w.Title}' ({w.ProcessName} #{w.Pid})",
                });
            }

            if (old != null && !old.IsFullScreen && w.IsFullScreen && !w.IsMinimized)
            {
                items.Add(new DiffItem
                {
                    Area = "Window",
                    Change = DiffChange.Changed,
                    Key = $"fullscreen|{h}",
                    Severity = Severity.Low,
                    Description = $"Went full-screen: '{w.Title}' ({w.ProcessName} #{w.Pid}) on {w.MonitorDevice}",
                });
            }
        }

        foreach (var (h, w) in before)
        {
            if (after.ContainsKey(h) || !w.IsCaptureProtected) continue;
            items.Add(new DiffItem
            {
                Area = "Window",
                Change = DiffChange.Removed,
                Key = $"affinity|{h}",
                Severity = Severity.Medium,
                Description = $"Capture-protected window closed: '{w.Title}' ({w.ProcessName} #{w.Pid})",
            });
        }

        var fgBefore = a.Windows.FirstOrDefault(w => w.IsForeground);
        var fgAfter = b.Windows.FirstOrDefault(w => w.IsForeground);
        if (fgAfter != null && fgBefore?.Pid != fgAfter.Pid && a.Windows.Count > 0)
        {
            items.Add(new DiffItem
            {
                Area = "Window",
                Change = DiffChange.Changed,
                Key = "foreground",
                Severity = Severity.Info,
                Description = $"Foreground application: {fgBefore?.ProcessName ?? "(none)"} -> {fgAfter.ProcessName} ('{fgAfter.Title}')",
            });
        }
    }

    private static void CompareDesktopAndSession(DisplayState? a, DisplayState? b, List<DiffItem> items)
    {
        if (a == null || b == null) return;
        var da = a.InputDesktopAccessible ? a.InputDesktopName : "(inaccessible - secure desktop)";
        var db = b.InputDesktopAccessible ? b.InputDesktopName : "(inaccessible - secure desktop)";
        if (!string.Equals(da, db, StringComparison.OrdinalIgnoreCase))
        {
            items.Add(new DiffItem
            {
                Area = "Desktop",
                Change = DiffChange.Changed,
                Key = "inputdesktop",
                Severity = b.IsOnAlternateDesktop ? Severity.Critical : Severity.Medium,
                Description = $"Input desktop changed: {da} -> {db}",
            });
        }

        if (a.NotificationState != b.NotificationState)
        {
            items.Add(new DiffItem
            {
                Area = "Display",
                Change = DiffChange.Changed,
                Key = "quns",
                Severity = b.NotificationState == DisplayState.QunsD3DFullScreen ? Severity.High : Severity.Low,
                Description = $"User notification state: {a.NotificationState} -> {b.NotificationState}",
            });
        }

        if (a.SessionLocked != b.SessionLocked && b.SessionLocked != null)
        {
            items.Add(new DiffItem
            {
                Area = "Session",
                Change = DiffChange.Changed,
                Key = "locked",
                Severity = b.SessionLocked == true ? Severity.High : Severity.Low,
                Description = b.SessionLocked == true ? "Windows session LOCKED" : "Windows session unlocked",
            });
        }

        if (a.ActiveConsoleSessionId != b.ActiveConsoleSessionId || a.OwnSessionConnectState != b.OwnSessionConnectState)
        {
            items.Add(new DiffItem
            {
                Area = "Session",
                Change = DiffChange.Changed,
                Key = "session",
                Severity = Severity.High,
                Description = $"Session change: console session {a.ActiveConsoleSessionId} -> {b.ActiveConsoleSessionId}, " +
                              $"this session state {a.OwnSessionConnectState} -> {b.OwnSessionConnectState}",
            });
        }
    }

    private static void CompareDisplay(DisplayState? a, DisplayState? b, List<DiffItem> items, bool topology, bool adapters)
    {
        if (a == null || b == null) return;
        if (topology && a.Monitors.Count > 0 && b.Monitors.Count > 0 && a.TopologyKey != b.TopologyKey)
        {
            items.Add(new DiffItem
            {
                Area = "Display",
                Change = DiffChange.Changed,
                Key = "topology",
                Severity = Severity.High,
                Description = $"Display configuration changed: [{string.Join(", ", a.Monitors)}] -> [{string.Join(", ", b.Monitors)}]",
            });
        }

        if (!adapters) return;
        var before = a.Adapters.ToDictionary(x => x.PnpDeviceId ?? x.Name, x => x);
        var after = b.Adapters.ToDictionary(x => x.PnpDeviceId ?? x.Name, x => x);
        foreach (var (k, v) in after)
        {
            if (!before.TryGetValue(k, out var old))
                items.Add(new DiffItem { Area = "Display", Change = DiffChange.Added, Key = "gpu|" + k, Severity = Severity.High, Description = $"Display adapter appeared: {v.Name}" });
            else if (old.Status != v.Status || old.DriverVersion != v.DriverVersion)
                items.Add(new DiffItem { Area = "Display", Change = DiffChange.Changed, Key = "gpu|" + k, Severity = Severity.High, Description = $"Display adapter {v.Name}: status {old.Status} -> {v.Status}, driver {old.DriverVersion} -> {v.DriverVersion}" });
        }
        foreach (var (k, v) in before)
            if (!after.ContainsKey(k))
                items.Add(new DiffItem { Area = "Display", Change = DiffChange.Removed, Key = "gpu|" + k, Severity = Severity.High, Description = $"Display adapter disappeared: {v.Name}" });
    }

    private static void CompareCapture(CaptureTestResult? a, CaptureTestResult? b, List<DiffItem> items)
    {
        if (a == null || b == null) return;
        var before = a.Monitors.ToDictionary(m => m.Name, m => m);
        foreach (var m in b.Monitors)
        {
            if (!before.TryGetValue(m.Name, out var old)) continue;
            var oldState = old.IsBlack ? "black" : old.Succeeded ? "ok" : "failed";
            var newState = m.IsBlack ? "black" : m.Succeeded ? "ok" : "failed";
            if (oldState == newState) continue;
            items.Add(new DiffItem
            {
                Area = "Capture",
                Change = DiffChange.Changed,
                Key = "capture|" + m.Name,
                Severity = newState == "ok" ? Severity.Medium : Severity.Critical,
                Description = $"Screen capture of {m.Name}: {old.StatusText} -> {m.StatusText}",
            });
        }
    }

    private static void CompareMesh(MeshAgentStatus? a, MeshAgentStatus? b, List<DiffItem> items)
    {
        if (a == null || b == null) return;
        if (a.Health != b.Health)
        {
            items.Add(new DiffItem
            {
                Area = "MeshAgent",
                Change = DiffChange.Changed,
                Key = "health",
                Severity = b.Health == "CONNECTED" ? Severity.Medium : Severity.Critical,
                Description = $"MeshCentral agent state: {a.Health} -> {b.Health}",
            });
        }

        var kvmBefore = a.Processes.Where(p => p.Role == "KVM").ToDictionary(p => p.Pid);
        var kvmAfter = b.Processes.Where(p => p.Role == "KVM").ToDictionary(p => p.Pid);
        foreach (var (pid, p) in kvmAfter)
            if (!kvmBefore.ContainsKey(pid))
                items.Add(new DiffItem { Area = "MeshAgent", Change = DiffChange.Added, Key = $"kvm|{pid}", Severity = Severity.Low, Description = $"MeshAgent KVM (remote desktop) process started: PID {pid}, session {p.SessionId}" });
        foreach (var (pid, p) in kvmBefore)
            if (!kvmAfter.ContainsKey(pid))
                items.Add(new DiffItem
                {
                    Area = "MeshAgent",
                    Change = DiffChange.Removed,
                    Key = $"kvm|{pid}",
                    Severity = kvmAfter.Count > 0 ? Severity.High : Severity.Medium,
                    Description = kvmAfter.Count > 0
                        ? $"MeshAgent KVM process RESTARTED (PID {pid} exited, replaced by PID {string.Join(",", kvmAfter.Keys)}) — possible capture crash"
                        : $"MeshAgent KVM process exited: PID {pid} (desktop session closed or KVM crashed)",
                });

        var svcBefore = a.Processes.Where(p => p.Role == "Service").Select(p => p.Pid).ToHashSet();
        var svcAfter = b.Processes.Where(p => p.Role == "Service").Select(p => p.Pid).ToHashSet();
        if (svcBefore.Count > 0 && svcAfter.Count > 0 && !svcBefore.SetEquals(svcAfter))
            items.Add(new DiffItem { Area = "MeshAgent", Change = DiffChange.Changed, Key = "svcpid", Severity = Severity.High, Description = $"MeshAgent service process restarted (PID {string.Join(",", svcBefore)} -> {string.Join(",", svcAfter)})" });
    }

    private static void CompareConnections(SystemSnapshot a, SystemSnapshot b, List<DiffItem> items)
    {
        if (a.Connections.Count == 0 && b.Connections.Count == 0) return;
        var before = a.Connections.GroupBy(c => c.Key).ToDictionary(g => g.Key, g => g.First());
        var after = b.Connections.GroupBy(c => c.Key).ToDictionary(g => g.Key, g => g.First());

        foreach (var (k, c) in after)
        {
            if (before.TryGetValue(k, out var old))
            {
                if (old.State != c.State && c.Protocol == "TCP" && c.IsMeshAgent)
                    items.Add(new DiffItem { Area = "Connection", Change = DiffChange.Changed, Key = k, Severity = Severity.High, Description = $"MeshAgent connection state {old.State} -> {c.State}: {c}" });
                continue;
            }
            // Only surface new listeners and MeshAgent connections individually; short-lived client
            // connections of other processes are too noisy to be useful here.
            if (c.IsMeshAgent || c.IsListening)
                items.Add(new DiffItem
                {
                    Area = "Connection",
                    Change = DiffChange.Added,
                    Key = k,
                    Severity = c.IsMeshAgent ? Severity.Medium : Severity.Info,
                    Description = (c.IsListening ? "New listener: " : "New connection: ") + c + $" — {c.Purpose}",
                });
        }
        foreach (var (k, c) in before)
        {
            if (after.ContainsKey(k)) continue;
            if (c.IsMeshAgent || c.IsListening)
                items.Add(new DiffItem
                {
                    Area = "Connection",
                    Change = DiffChange.Removed,
                    Key = k,
                    Severity = c.IsMeshAgent && c.IsEstablished ? Severity.High : Severity.Info,
                    Description = (c.IsListening ? "Listener closed: " : "Connection closed: ") + c,
                });
        }
    }

    private static void CompareDrivers(SystemSnapshot a, SystemSnapshot b, List<DiffItem> items)
    {
        if (a.LoadedDrivers.Count == 0 || b.LoadedDrivers.Count == 0) return;
        var before = a.LoadedDrivers.Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var after = b.LoadedDrivers.Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var d in b.LoadedDrivers.Where(d => !before.Contains(d.Name)))
        {
            var known = KnownSoftwareCatalog.Match(d.Name);
            items.Add(new DiffItem
            {
                Area = "Driver",
                Change = DiffChange.Added,
                Key = d.Name,
                Severity = known != null ? Severity.High : Severity.Medium,
                Description = $"Kernel driver loaded: {d.Name} {d.Path}" + (known != null ? $" — known: {known.Product}" : ""),
            });
        }
        foreach (var d in a.LoadedDrivers.Where(d => !after.Contains(d.Name)))
            items.Add(new DiffItem { Area = "Driver", Change = DiffChange.Removed, Key = d.Name, Severity = Severity.Low, Description = $"Kernel driver unloaded: {d.Name}" });
    }

    private static void CompareServices(SystemSnapshot a, SystemSnapshot b, List<DiffItem> items)
    {
        var before = a.Services.GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        var after = b.Services.GroupBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
        foreach (var (k, s) in after)
        {
            var known = KnownSoftwareCatalog.Match(s.Name) ?? KnownSoftwareCatalog.Match(FileNameOf(s.PathName));
            if (!before.TryGetValue(k, out var old))
            {
                items.Add(new DiffItem { Area = s.Type, Change = DiffChange.Added, Key = k, Severity = Severity.High, Description = $"{s.Type} installed: {s.Name} ({s.DisplayName}) state {s.State}, {s.PathName}" + (known != null ? $" — known: {known.Product}" : "") });
            }
            else if (!string.Equals(old.State, s.State, StringComparison.OrdinalIgnoreCase) || !string.Equals(old.StartMode, s.StartMode, StringComparison.OrdinalIgnoreCase))
            {
                items.Add(new DiffItem
                {
                    Area = s.Type,
                    Change = DiffChange.Changed,
                    Key = k,
                    Severity = known != null || IsMeshName(s.Name) || IsMeshName(s.PathName) ? Severity.High : Severity.Low,
                    Description = $"{s.Type} {s.Name} ({s.DisplayName}): {old.State}/{old.StartMode} -> {s.State}/{s.StartMode}" + (known != null ? $" — known: {known.Product}" : ""),
                });
            }
        }
        foreach (var (k, s) in before)
            if (!after.ContainsKey(k))
                items.Add(new DiffItem { Area = s.Type, Change = DiffChange.Removed, Key = k, Severity = Severity.Medium, Description = $"{s.Type} removed: {s.Name} ({s.DisplayName})" });
    }

    private static void CompareFirewall(FirewallState? a, FirewallState? b, List<DiffItem> items)
    {
        if (a == null || b == null || a.Error != null || b.Error != null) return;

        var pa = a.Profiles.ToDictionary(p => p.Name);
        foreach (var p in b.Profiles)
        {
            if (!pa.TryGetValue(p.Name, out var old)) continue;
            if (old.Enabled != p.Enabled || old.DefaultOutboundAction != p.DefaultOutboundAction || old.DefaultInboundAction != p.DefaultInboundAction || old.BlockAllInbound != p.BlockAllInbound || old.IsActive != p.IsActive)
                items.Add(new DiffItem
                {
                    Area = "FirewallProfile",
                    Change = DiffChange.Changed,
                    Key = p.Name,
                    Severity = p.DefaultOutboundAction.Equals("Block", StringComparison.OrdinalIgnoreCase) ? Severity.High : Severity.Medium,
                    Description = $"Firewall profile {p.Name}: enabled {old.Enabled}->{p.Enabled}, active {old.IsActive}->{p.IsActive}, inbound {old.DefaultInboundAction}->{p.DefaultInboundAction}, outbound {old.DefaultOutboundAction}->{p.DefaultOutboundAction}, block-all-inbound {old.BlockAllInbound}->{p.BlockAllInbound}",
                });
        }

        var before = a.Rules.GroupBy(r => r.Key).ToDictionary(g => g.Key, g => g.First());
        var after = b.Rules.GroupBy(r => r.Key).ToDictionary(g => g.Key, g => g.First());
        foreach (var (k, r) in after)
        {
            if (!before.TryGetValue(k, out var old))
                items.Add(new DiffItem { Area = "FirewallRule", Change = DiffChange.Added, Key = k, Severity = RuleSeverity(r), Description = $"Firewall rule added: {r}" });
            else if (old.Fingerprint != r.Fingerprint)
                items.Add(new DiffItem { Area = "FirewallRule", Change = DiffChange.Changed, Key = k, Severity = RuleSeverity(r), Description = $"Firewall rule changed: {old} -> {r}" });
        }
        foreach (var (k, r) in before)
            if (!after.ContainsKey(k))
                items.Add(new DiffItem { Area = "FirewallRule", Change = DiffChange.Removed, Key = k, Severity = IsMeshName(r.Application) || IsMeshName(r.Name) ? Severity.High : Severity.Low, Description = $"Firewall rule removed: {r}" });
    }

    private static Severity RuleSeverity(FirewallRuleInfo r)
    {
        var block = r.Enabled && r.Action.Equals("Block", StringComparison.OrdinalIgnoreCase);
        if (block && (IsMeshName(r.Application) || IsMeshName(r.Name))) return Severity.Critical;
        if (block && r.Direction.Equals("Out", StringComparison.OrdinalIgnoreCase)) return Severity.High;
        return block ? Severity.Medium : Severity.Low;
    }

    private static void CompareSecurity(SystemSnapshot a, SystemSnapshot b, List<DiffItem> items)
    {
        var before = a.SecurityProducts.GroupBy(p => p.Key).ToDictionary(g => g.Key, g => g.First());
        var after = b.SecurityProducts.GroupBy(p => p.Key).ToDictionary(g => g.Key, g => g.First());
        foreach (var (k, p) in after)
        {
            if (!before.TryGetValue(k, out var old))
                items.Add(new DiffItem { Area = "SecurityProduct", Change = DiffChange.Added, Key = k, Severity = Severity.Medium, Description = $"Security product registered: {p.Kind} {p.Name} (enabled {p.Enabled})" });
            else if (old.ProductState != p.ProductState)
                items.Add(new DiffItem { Area = "SecurityProduct", Change = DiffChange.Changed, Key = k, Severity = Severity.Medium, Description = $"Security product {p.Kind} {p.Name}: enabled {old.Enabled}->{p.Enabled}, up-to-date {old.UpToDate}->{p.UpToDate}" });
        }
        foreach (var (k, p) in before)
            if (!after.ContainsKey(k))
                items.Add(new DiffItem { Area = "SecurityProduct", Change = DiffChange.Removed, Key = k, Severity = Severity.Medium, Description = $"Security product unregistered: {p.Kind} {p.Name}" });

        if (a.Defender != null && b.Defender != null && a.Defender.RealTimeProtectionEnabled != b.Defender.RealTimeProtectionEnabled)
            items.Add(new DiffItem { Area = "SecurityProduct", Change = DiffChange.Changed, Key = "defender-rtp", Severity = Severity.Medium, Description = $"Defender real-time protection: {a.Defender.RealTimeProtectionEnabled} -> {b.Defender.RealTimeProtectionEnabled}" });
    }

    private static Severity SeverityForKnown(KnownSoftwareKind kind) => kind switch
    {
        KnownSoftwareKind.CaptureProtection or KnownSoftwareKind.DesktopSwitch or KnownSoftwareKind.ProtectedMedia or KnownSoftwareKind.WindowsState => Severity.High,
        KnownSoftwareKind.DataLossPrevention or KnownSoftwareKind.RemoteAccess or KnownSoftwareKind.VirtualDisplay => Severity.Medium,
        _ => Severity.Low,
    };

    public static bool IsMeshName(string? s) =>
        s != null && s.Contains("mesh", StringComparison.OrdinalIgnoreCase);

    private static string? FileNameOf(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var p = path.Trim();
        if (p.StartsWith('"'))
        {
            var end = p.IndexOf('"', 1);
            p = end > 0 ? p[1..end] : p.Trim('"');
        }
        else
        {
            var exe = p.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exe > 0) p = p[..(exe + 4)];
        }
        return System.IO.Path.GetFileName(p.Replace('\\', '/'));
    }
}
