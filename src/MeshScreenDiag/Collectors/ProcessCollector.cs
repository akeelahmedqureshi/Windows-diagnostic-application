using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using MeshScreenDiag.Core.Catalogs;
using MeshScreenDiag.Core.Models;
using static MeshScreenDiag.Native.NativeMethods;

namespace MeshScreenDiag.Collectors;

/// <summary>
/// Enumerates processes with Toolhelp32 (cheap) and enriches them with path, start time, session,
/// publisher and signer. Per-file details are cached so a 2-second polling loop stays light.
/// </summary>
internal sealed class ProcessCollector
{
    private readonly ConcurrentDictionary<string, (string? company, string? description)> _versionCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, string?> _signerCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, (DateTime? start, string? path, int session)> _pidCache = new();
    private readonly Dictionary<string, (DateTime when, List<string> indicators)> _moduleCache = new();

    public List<ProcessInfo> Collect(bool enrichPublisher, List<string> errors)
    {
        var list = new List<ProcessInfo>(256);
        var snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
        {
            errors.Add($"Process enumeration failed (Win32 error {Marshal.GetLastWin32Error()})");
            return list;
        }

        try
        {
            var entry = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref entry)) return list;
            var seen = new HashSet<int>();
            do
            {
                var pid = (int)entry.th32ProcessID;
                seen.Add(pid);
                var p = new ProcessInfo { Pid = pid, ParentPid = (int)entry.th32ParentProcessID, Name = entry.szExeFile };
                FillBasics(p);
                list.Add(p);
            } while (Process32NextW(snap, ref entry));

            // Forget PIDs that went away so a reused PID gets fresh data.
            foreach (var stale in _pidCache.Keys.Where(k => !seen.Contains(k)).ToList()) _pidCache.Remove(stale);
        }
        finally
        {
            CloseHandle(snap);
        }

        if (enrichPublisher)
        {
            foreach (var p in list.Where(p => p.Path != null))
            {
                var (company, description) = _versionCache.GetOrAdd(p.Path!, ReadVersionInfo);
                p.Company = company;
                p.Description = description;
                p.Signer = _signerCache.GetOrAdd(p.Path!, ReadSigner);
            }
        }
        else
        {
            foreach (var p in list.Where(p => p.Path != null))
            {
                if (_versionCache.TryGetValue(p.Path!, out var v)) (p.Company, p.Description) = v;
                if (_signerCache.TryGetValue(p.Path!, out var s)) p.Signer = s;
            }
        }
        return list;
    }

    private void FillBasics(ProcessInfo p)
    {
        if (p.Pid == 0) { p.SessionId = 0; return; }
        if (_pidCache.TryGetValue(p.Pid, out var cached))
        {
            p.StartTimeUtc = cached.start;
            p.Path = cached.path;
            p.SessionId = cached.session;
            // Verify it is still the same process (PID reuse): the start time must match.
            if (cached.start == null || cached.start == GetStartTime(p.Pid)) return;
        }

        p.SessionId = ProcessIdToSessionId(p.Pid, out var sid) ? sid : -1;
        p.StartTimeUtc = GetStartTime(p.Pid);
        p.Path = GetPath(p.Pid);
        _pidCache[p.Pid] = (p.StartTimeUtc, p.Path, p.SessionId);
    }

    public static DateTime? GetStartTime(int pid)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            return GetProcessTimes(h, out var creation, out _, out _, out _) && creation > 0
                ? DateTime.FromFileTimeUtc(creation)
                : null;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    public static string? GetPath(int pid)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            var size = sb.Capacity;
            return QueryFullProcessImageNameW(h, 0, sb, ref size) ? sb.ToString(0, size) : null;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    /// <summary>Returns "Untrusted", "Low", "Medium", "High" or "System" (null if not readable).</summary>
    public static string? GetIntegrityLevel(int pid)
    {
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            if (!OpenProcessToken(h, TOKEN_QUERY, out var token)) return null;
            try
            {
                GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out var len);
                if (len <= 0) return null;
                var buf = Marshal.AllocHGlobal(len);
                try
                {
                    if (!GetTokenInformation(token, TokenIntegrityLevel, buf, len, out _)) return null;
                    var sid = Marshal.ReadIntPtr(buf); // TOKEN_MANDATORY_LABEL.Label.Sid
                    var count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                    var rid = (uint)Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
                    return rid switch
                    {
                        < 0x1000 => "Untrusted",
                        < 0x2000 => "Low",
                        < 0x3000 => "Medium",
                        < 0x4000 => "High",
                        _ => "System",
                    };
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            finally
            {
                CloseHandle(token);
            }
        }
        finally
        {
            CloseHandle(h);
        }
    }

    /// <summary>
    /// Lists rendering / DRM related modules loaded by a process (Direct3D, PlayReady, ...).
    /// Needs PROCESS_VM_READ, so it only works for processes of the same user (or everything when elevated).
    /// </summary>
    public List<string> GetModuleIndicators(ProcessInfo p)
    {
        if (_moduleCache.TryGetValue(p.Key, out var c) && DateTime.UtcNow - c.when < TimeSpan.FromSeconds(10))
            return c.indicators;

        var result = new List<string>();
        var h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, p.Pid);
        if (h != IntPtr.Zero)
        {
            try
            {
                if (EnumProcessModulesEx(h, null, 0, out var needed, LIST_MODULES_ALL) && needed > 0)
                {
                    var count = (int)(needed / (uint)IntPtr.Size);
                    var mods = new IntPtr[count + 16];
                    if (EnumProcessModulesEx(h, mods, (uint)(mods.Length * IntPtr.Size), out needed, LIST_MODULES_ALL))
                    {
                        count = Math.Min(mods.Length, (int)(needed / (uint)IntPtr.Size));
                        var sb = new StringBuilder(260);
                        for (var i = 0; i < count; i++)
                        {
                            sb.Clear();
                            if (GetModuleBaseNameW(h, mods[i], sb, (uint)sb.Capacity) == 0) continue;
                            if (KnownSoftwareCatalog.ModuleIndicators.TryGetValue(sb.ToString(), out var ind) && !result.Contains(ind))
                                result.Add(ind);
                        }
                    }
                }
            }
            finally
            {
                CloseHandle(h);
            }
        }

        if (_moduleCache.Count > 500) _moduleCache.Clear();
        _moduleCache[p.Key] = (DateTime.UtcNow, result);
        return result;
    }

    private static (string?, string?) ReadVersionInfo(string path)
    {
        try
        {
            var vi = FileVersionInfo.GetVersionInfo(path);
            return (string.IsNullOrWhiteSpace(vi.CompanyName) ? null : vi.CompanyName.Trim(),
                    string.IsNullOrWhiteSpace(vi.FileDescription) ? null : vi.FileDescription.Trim());
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>Subject CN of an embedded Authenticode signature (catalog-signed Windows files have none).</summary>
    private static string? ReadSigner(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch
        {
            return null;
        }
    }
}
