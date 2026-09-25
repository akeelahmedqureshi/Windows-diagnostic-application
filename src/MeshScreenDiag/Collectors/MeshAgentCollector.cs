using System.Management;
using System.Net;
using System.ServiceProcess;
using MeshScreenDiag.Core.Models;
using static MeshScreenDiag.Native.NativeMethods;

namespace MeshScreenDiag.Collectors;

/// <summary>
/// Finds the MeshCentral agent (service, main process and the per-session KVM child that does the
/// remote-desktop capture), reads the server address from the agent's .msh file and measures whether
/// the agent is connected and actively transferring data.
/// </summary>
internal sealed class MeshAgentCollector
{
    private static readonly string[] DefaultNames = { "MeshAgent", "meshagent", "MeshCentralAssistant" };

    private readonly Dictionary<int, (DateTime t, long cpu, ulong io)> _prevCounters = new();
    private readonly Dictionary<int, string?> _cmdLineCache = new();
    private (string? name, string? display, string? path, int pid, string? startMode)? _service;
    private (DateTime at, string host, List<string> addrs)? _dnsCache;
    private IReadOnlyList<string> _extraNames = Array.Empty<string>();

    public void Configure(IReadOnlyList<string> extraNames) => _extraNames = extraNames;

    /// <summary>Re-identifies the agent service from the full service list (called on full snapshots).</summary>
    public void UpdateServiceIdentity(IEnumerable<ServiceInfo> services)
    {
        var svc = services.FirstOrDefault(s => s.Type == "Service" && IsAgentService(s));
        _service = svc == null ? null : (svc.Name, svc.DisplayName, ExeFromCommandLine(svc.PathName), svc.ProcessId, svc.StartMode);
    }

    private bool IsAgentService(ServiceInfo s) =>
        s.Name.Equals("Mesh Agent", StringComparison.OrdinalIgnoreCase) ||
        (s.PathName?.Contains("meshagent", StringComparison.OrdinalIgnoreCase) ?? false) ||
        _extraNames.Any(n => s.Name.Equals(n, StringComparison.OrdinalIgnoreCase) || s.DisplayName.Equals(n, StringComparison.OrdinalIgnoreCase) ||
                             (s.PathName?.Contains(n, StringComparison.OrdinalIgnoreCase) ?? false));

    private bool IsAgentProcessName(string name)
    {
        var baseName = Path.GetFileNameWithoutExtension(name);
        return DefaultNames.Any(n => baseName.StartsWith(n, StringComparison.OrdinalIgnoreCase)) ||
               _extraNames.Any(n => baseName.Equals(Path.GetFileNameWithoutExtension(n), StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>PIDs of all agent processes (used to tag network connections).</summary>
    public HashSet<int> FindAgentPids(IEnumerable<ProcessInfo> processes)
    {
        var exe = _service?.path;
        return processes.Where(p =>
                IsAgentProcessName(p.Name) ||
                (exe != null && p.Path != null && p.Path.Equals(exe, StringComparison.OrdinalIgnoreCase)))
            .Select(p => p.Pid)
            .ToHashSet();
    }

    public MeshAgentStatus Collect(IReadOnlyList<ProcessInfo> processes, IReadOnlyList<NetConnection> connections, HashSet<int> agentPids, bool resolveDns)
    {
        var st = new MeshAgentStatus();

        // Service state (cheap; ServiceController does not need WMI).
        if (_service is { } svc)
        {
            st.ServiceName = svc.name;
            st.ServiceStartMode = svc.startMode;
            try
            {
                using var sc = new ServiceController(svc.name!);
                st.ServiceState = sc.Status.ToString();
            }
            catch (Exception ex)
            {
                st.ServiceState = "unknown (" + ex.Message + ")";
            }
        }
        else
        {
            try
            {
                using var sc = new ServiceController("Mesh Agent");
                st.ServiceState = sc.Status.ToString();
                st.ServiceName = "Mesh Agent";
            }
            catch
            {
                // Not installed as the default service name.
            }
        }

        var agentProcs = processes.Where(p => agentPids.Contains(p.Pid)).ToList();
        var exePath = _service?.path ?? agentProcs.Select(p => p.Path).FirstOrDefault(p => p != null);
        st.InstallPath = exePath != null ? Path.GetDirectoryName(exePath) : null;
        st.Found = st.ServiceName != null || agentProcs.Count > 0;
        if (!st.Found)
        {
            st.Notes.Add("No 'Mesh Agent' service and no MeshAgent/MeshCentralAssistant process found. If the agent is branded, add its name in Settings.");
            return st;
        }

        var now = DateTime.UtcNow;
        var mainPid = _service?.pid ?? 0;
        foreach (var p in agentProcs)
        {
            var cmd = GetCommandLine(p.Pid);
            var role = p.Pid == mainPid && mainPid != 0 ? "Service"
                : cmd != null && cmd.Contains("-kvm", StringComparison.OrdinalIgnoreCase) ? "KVM"
                : p.SessionId > 0 && agentProcs.Any(a => a.Pid == p.ParentPid) ? "KVM"
                : p.SessionId == 0 && !agentProcs.Any(a => a.Pid == p.ParentPid) ? "Service"
                : "Child";
            var mp = new MeshAgentProcess
            {
                Pid = p.Pid,
                Name = p.Name,
                Path = p.Path,
                SessionId = p.SessionId,
                Role = role,
                CommandLine = cmd,
                StartTimeUtc = p.StartTimeUtc,
            };
            SampleCounters(mp, now);
            st.Processes.Add(mp);
        }
        foreach (var gone in _prevCounters.Keys.Where(k => !agentPids.Contains(k)).ToList()) _prevCounters.Remove(gone);

        ReadMsh(st);
        if (resolveDns && st.ServerHost != null) ResolveServer(st);
        else if (_dnsCache is { } c && c.host == st.ServerHost) st.ServerAddresses = c.addrs;

        st.Connections = connections.Where(c => agentPids.Contains(c.Pid)).ToList();
        var established = st.Connections.Where(c => c.Protocol == "TCP" && c.IsEstablished && !IsLoopback(c.RemoteAddress)).ToList();
        if (st.ServerAddresses.Count > 0)
        {
            var toServer = established.Where(c => st.ServerAddresses.Contains(Normalize(c.RemoteAddress))).ToList();
            st.ServerConnected = established.Count > 0;
            if (toServer.Count == 0 && established.Count > 0)
                st.Notes.Add($"Agent has established connections, but not to the resolved server address ({string.Join(", ", st.ServerAddresses)}): probably via a proxy, load balancer or CDN — connected to {string.Join(", ", established.Select(e => $"{e.RemoteAddress}:{e.RemotePort}").Distinct())}");
        }
        else
        {
            st.ServerConnected = established.Count > 0;
        }

        if (!st.Processes.Any(p => p.Role == "KVM"))
            st.Notes.Add("No KVM child process: the MeshCentral Desktop tab is not connected right now (the agent starts a KVM process in the user's session when someone opens it).");
        if (st.Processes.All(p => p.CommandLine == null) && !IsElevated())
            st.Notes.Add("Agent command lines and I/O counters of SYSTEM processes need administrator rights.");
        return st;
    }

    private void SampleCounters(MeshAgentProcess mp, DateTime now)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, mp.Pid);
        if (h == IntPtr.Zero) return;
        try
        {
            long cpu = 0;
            ulong io = 0;
            var haveCpu = GetProcessTimes(h, out _, out _, out var kernel, out var user);
            if (haveCpu) cpu = kernel + user;
            var haveIo = GetProcessIoCounters(h, out var ioc);
            if (haveIo) io = ioc.ReadTransferCount + ioc.WriteTransferCount + ioc.OtherTransferCount;

            if (_prevCounters.TryGetValue(mp.Pid, out var prev))
            {
                var dt = (now - prev.t).TotalSeconds;
                if (dt > 0.2)
                {
                    if (haveCpu) mp.CpuPercent = Math.Max(0, (cpu - prev.cpu) / 1e7 / dt / Environment.ProcessorCount * 100);
                    if (haveIo) mp.IoBytesPerSec = io >= prev.io ? (io - prev.io) / dt : 0;
                }
            }
            if (haveCpu || haveIo) _prevCounters[mp.Pid] = (now, cpu, io);
        }
        finally
        {
            CloseHandle(h);
        }
    }

    private string? GetCommandLine(int pid)
    {
        if (_cmdLineCache.TryGetValue(pid, out var cached)) return cached;
        string? cmd = null;
        try
        {
            using var searcher = new ManagementObjectSearcher("root\\CIMV2", $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
            foreach (ManagementObject mo in searcher.Get())
                using (mo)
                    cmd = mo["CommandLine"]?.ToString();
        }
        catch
        {
            // Access denied for SYSTEM processes when not elevated.
        }
        if (_cmdLineCache.Count > 200) _cmdLineCache.Clear();
        _cmdLineCache[pid] = cmd;
        return cmd;
    }

    private static void ReadMsh(MeshAgentStatus st)
    {
        if (st.InstallPath == null || !Directory.Exists(st.InstallPath)) return;
        try
        {
            var msh = Directory.EnumerateFiles(st.InstallPath, "*.msh").FirstOrDefault();
            if (msh == null)
            {
                st.Notes.Add("No .msh settings file next to the agent executable (settings may be embedded in the agent).");
                return;
            }
            foreach (var line in File.ReadLines(msh))
            {
                var eq = line.IndexOf('=');
                if (eq <= 0) continue;
                var key = line[..eq].Trim();
                var val = line[(eq + 1)..].Trim();
                // Only non-secret values are read (no MeshID / ServerID / certificates).
                if (key.Equals("MeshServer", StringComparison.OrdinalIgnoreCase)) st.ServerUrl = val;
                else if (key.Equals("MeshName", StringComparison.OrdinalIgnoreCase)) st.MeshName = val;
            }
            if (st.ServerUrl == null) return;
            if (st.ServerUrl.Equals("local", StringComparison.OrdinalIgnoreCase))
            {
                st.Notes.Add("Agent is in LAN mode (MeshServer=local): it finds the server by multicast discovery.");
                return;
            }
            if (Uri.TryCreate(st.ServerUrl, UriKind.Absolute, out var uri))
            {
                st.ServerHost = uri.Host;
                st.ServerPort = uri.IsDefaultPort ? (uri.Scheme is "wss" or "https" ? 443 : 80) : uri.Port;
            }
        }
        catch (Exception ex)
        {
            st.Notes.Add("Could not read the agent .msh file: " + ex.Message);
        }
    }

    private void ResolveServer(MeshAgentStatus st)
    {
        var host = st.ServerHost!;
        if (_dnsCache is { } c && c.host == host && DateTime.UtcNow - c.at < TimeSpan.FromMinutes(5))
        {
            st.ServerAddresses = c.addrs;
            return;
        }
        try
        {
            var addrs = IPAddress.TryParse(host, out var ip)
                ? new List<string> { Normalize(ip.ToString()) }
                : Dns.GetHostAddresses(host).Select(a => Normalize(a.ToString())).Distinct().ToList();
            _dnsCache = (DateTime.UtcNow, host, addrs);
            st.ServerAddresses = addrs;
        }
        catch (Exception ex)
        {
            st.Notes.Add($"DNS lookup of the MeshCentral server '{host}' failed: {ex.Message}");
            _dnsCache = (DateTime.UtcNow, host, new List<string>());
        }
    }

    private static string Normalize(string addr) =>
        IPAddress.TryParse(addr, out var ip) && ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : addr;

    private static bool IsLoopback(string addr) =>
        IPAddress.TryParse(addr, out var ip) && (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any));

    private static bool IsElevated()
    {
        using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /// <summary>Extracts the executable path from a service PathName such as <c>"C:\Program Files\Mesh Agent\MeshAgent.exe" -svc</c>.</summary>
    public static string? ExeFromCommandLine(string? cmd)
    {
        if (string.IsNullOrWhiteSpace(cmd)) return null;
        cmd = cmd.Trim();
        if (cmd.StartsWith('"'))
        {
            var end = cmd.IndexOf('"', 1);
            return end > 1 ? cmd[1..end] : cmd.Trim('"');
        }
        var exe = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? cmd[..(exe + 4)] : cmd.Split(' ')[0];
    }
}
