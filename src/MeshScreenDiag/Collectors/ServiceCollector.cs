using System.Management;
using System.Text;
using MeshScreenDiag.Core.Models;
using static MeshScreenDiag.Native.NativeMethods;

namespace MeshScreenDiag.Collectors;

/// <summary>Services and drivers registered with the SCM (WMI) plus the kernel modules currently loaded.</summary>
internal static class ServiceCollector
{
    public static List<ServiceInfo> GetServicesAndDrivers(List<string> errors)
    {
        var list = new List<ServiceInfo>(600);
        Query(list, "SELECT Name, DisplayName, State, StartMode, PathName, ProcessId FROM Win32_Service", "Service", errors);
        Query(list, "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_SystemDriver", "Driver", errors);
        return list;
    }

    private static void Query(List<ServiceInfo> list, string wql, string type, List<string> errors)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher("root\\CIMV2", wql);
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    list.Add(new ServiceInfo
                    {
                        Name = mo["Name"]?.ToString() ?? "",
                        DisplayName = mo["DisplayName"]?.ToString() ?? "",
                        State = mo["State"]?.ToString() ?? "",
                        StartMode = mo["StartMode"]?.ToString() ?? "",
                        PathName = mo["PathName"]?.ToString(),
                        ProcessId = type == "Service" && mo["ProcessId"] is uint pid ? (int)pid : 0,
                        Type = type,
                    });
                }
            }
        }
        catch (Exception ex)
        {
            errors.Add($"{type}s (WMI): {ex.Message}");
        }
    }

    /// <summary>Kernel modules loaded right now (EnumDeviceDrivers). Cheap enough for every monitoring tick.</summary>
    public static List<LoadedDriverInfo> GetLoadedDrivers(List<string> errors)
    {
        var result = new List<LoadedDriverInfo>();
        if (!EnumDeviceDrivers(null, 0, out var needed) || needed == 0)
        {
            errors.Add("Loaded kernel drivers: EnumDeviceDrivers failed (administrator rights may be required)");
            return result;
        }
        var bases = new IntPtr[needed / (uint)IntPtr.Size + 32];
        if (!EnumDeviceDrivers(bases, (uint)(bases.Length * IntPtr.Size), out needed)) return result;
        var count = Math.Min(bases.Length, (int)(needed / (uint)IntPtr.Size));
        var sb = new StringBuilder(512);
        var zeroBases = 0;
        for (var i = 0; i < count; i++)
        {
            if (bases[i] == IntPtr.Zero) { zeroBases++; continue; }
            sb.Clear();
            if (GetDeviceDriverBaseNameW(bases[i], sb, (uint)sb.Capacity) == 0) continue;
            var name = sb.ToString();
            sb.Clear();
            var path = GetDeviceDriverFileNameW(bases[i], sb, (uint)sb.Capacity) > 0 ? NormalizeDriverPath(sb.ToString()) : null;
            result.Add(new LoadedDriverInfo { Name = name, Path = path });
        }
        // Newer Windows builds hide kernel addresses from non-admin callers, which makes names unreadable.
        if (result.Count == 0 && zeroBases > 0)
            errors.Add("Loaded kernel drivers: addresses hidden for non-administrators — run elevated to list loaded drivers");
        return result;
    }

    private static string NormalizeDriverPath(string p)
    {
        if (p.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), p[12..]);
        if (p.StartsWith(@"\??\", StringComparison.Ordinal))
            return p[4..];
        return p;
    }
}
