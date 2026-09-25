using System.Management;
using System.Runtime.InteropServices;
using MeshScreenDiag.Core.Models;
using Microsoft.Win32;
using static MeshScreenDiag.Native.NativeMethods;

namespace MeshScreenDiag.Collectors;

/// <summary>Monitors, GPU adapters, the active input desktop, user-notification state and session state.</summary>
internal static class DisplayCollector
{
    public static List<MonitorInfo> GetMonitors()
    {
        var result = new List<MonitorInfo>();
        EnumDisplayMonitors(IntPtr.Zero, IntPtr.Zero, (IntPtr hMon, IntPtr _, ref RECT _, IntPtr _) =>
        {
            var mi = new MONITORINFOEX { cbSize = Marshal.SizeOf<MONITORINFOEX>(), szDevice = "" };
            if (GetMonitorInfoW(hMon, ref mi))
            {
                var m = new MonitorInfo
                {
                    DeviceName = mi.szDevice,
                    Bounds = new RectI(mi.rcMonitor.Left, mi.rcMonitor.Top, mi.rcMonitor.Right, mi.rcMonitor.Bottom),
                    IsPrimary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0,
                };
                var dm = new DEVMODE { dmDeviceName = "", dmFormName = "", dmSize = (short)Marshal.SizeOf<DEVMODE>() };
                if (EnumDisplaySettingsW(mi.szDevice, ENUM_CURRENT_SETTINGS, ref dm))
                {
                    m.BitsPerPixel = dm.dmBitsPerPel;
                    m.RefreshRateHz = dm.dmDisplayFrequency;
                }
                m.AdapterName = GetAdapterForDevice(mi.szDevice);
                result.Add(m);
            }
            return true;
        }, IntPtr.Zero);
        return result;
    }

    private static string? GetAdapterForDevice(string deviceName)
    {
        var dd = new DISPLAY_DEVICE { cb = Marshal.SizeOf<DISPLAY_DEVICE>(), DeviceName = "", DeviceString = "", DeviceID = "", DeviceKey = "" };
        for (uint i = 0; EnumDisplayDevicesW(null, i, ref dd, 0); i++)
        {
            if (string.Equals(dd.DeviceName, deviceName, StringComparison.OrdinalIgnoreCase)) return dd.DeviceString;
            dd.cb = Marshal.SizeOf<DISPLAY_DEVICE>();
        }
        return null;
    }

    public static List<GpuAdapterInfo> GetAdapters(List<string> errors)
    {
        var list = new List<GpuAdapterInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher("root\\CIMV2",
                "SELECT Name, DriverVersion, DriverDate, Status, AdapterCompatibility, PNPDeviceID, VideoModeDescription FROM Win32_VideoController");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    list.Add(new GpuAdapterInfo
                    {
                        Name = mo["Name"]?.ToString() ?? "",
                        DriverVersion = mo["DriverVersion"]?.ToString(),
                        DriverDate = FormatWmiDate(mo["DriverDate"]?.ToString()),
                        Status = mo["Status"]?.ToString(),
                        Vendor = mo["AdapterCompatibility"]?.ToString(),
                        PnpDeviceId = mo["PNPDeviceID"]?.ToString(),
                        CurrentMode = mo["VideoModeDescription"]?.ToString(),
                    });
                }
            }
        }
        catch (Exception ex)
        {
            errors.Add("GPU adapters (WMI Win32_VideoController): " + ex.Message);
        }
        return list;
    }

    private static string? FormatWmiDate(string? s)
    {
        if (string.IsNullOrEmpty(s)) return null;
        try { return ManagementDateTimeConverter.ToDateTime(s).ToString("yyyy-MM-dd"); }
        catch { return s; }
    }

    public static DisplayState GetState(bool includeAdapters, List<string> errors)
    {
        var d = new DisplayState { Monitors = GetMonitors() };
        if (includeAdapters) d.Adapters = GetAdapters(errors);

        // Input desktop: the desktop currently shown and receiving input.
        var hDesk = OpenInputDesktop(0, false, DESKTOP_READOBJECTS);
        if (hDesk == IntPtr.Zero)
        {
            d.InputDesktopAccessible = false;
            d.InputDesktopError = Marshal.GetLastWin32Error();
        }
        else
        {
            d.InputDesktopName = GetObjectName(hDesk);
            CloseDesktop(hDesk);
        }
        var own = GetThreadDesktop(GetCurrentThreadId());
        if (own != IntPtr.Zero) d.OwnDesktopName = GetObjectName(own);

        d.NotificationState = SHQueryUserNotificationState(out var quns) == 0 ? QunsName(quns) : "unknown";

        d.ActiveConsoleSessionId = WTSGetActiveConsoleSessionId();
        d.OwnSessionId = ProcessIdToSessionId(Environment.ProcessId, out var sid) ? sid : -1;
        d.IsRemoteSession = GetSystemMetrics(SM_REMOTESESSION) != 0;
        (d.OwnSessionConnectState, d.SessionLocked) = GetSessionState(d.OwnSessionId);

        try
        {
            using var dwm = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\Dwm");
            d.MpoDisabled = dwm?.GetValue("OverlayTestMode") is int otm && otm == 5;
            using var gd = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\GraphicsDrivers");
            d.HagsMode = gd?.GetValue("HwSchMode") as int?;
        }
        catch (Exception ex)
        {
            errors.Add("Display registry settings: " + ex.Message);
        }
        return d;
    }

    private static string? GetObjectName(IntPtr handle)
    {
        GetUserObjectInformationW(handle, UOI_NAME, null, 0, out var needed);
        if (needed == 0) return null;
        var buf = new char[needed / 2 + 1];
        return GetUserObjectInformationW(handle, UOI_NAME, buf, (uint)(buf.Length * 2), out _)
            ? new string(buf).TrimEnd('\0')
            : null;
    }

    private static string QunsName(int v) => v switch
    {
        1 => DisplayState.QunsNotPresent,
        2 => DisplayState.QunsBusy,
        3 => DisplayState.QunsD3DFullScreen,
        4 => DisplayState.QunsPresentation,
        5 => "QUNS_ACCEPTS_NOTIFICATIONS",
        6 => "QUNS_QUIET_TIME",
        7 => "QUNS_APP",
        _ => $"QUNS_{v}",
    };

    private static (string?, bool?) GetSessionState(int sessionId)
    {
        string? state = null;
        bool? locked = null;
        if (sessionId < 0) return (null, null);

        if (WTSQuerySessionInformationW(IntPtr.Zero, sessionId, WTSConnectState, out var buf, out _) && buf != IntPtr.Zero)
        {
            state = Marshal.ReadInt32(buf) switch
            {
                0 => "Active", 1 => "Connected", 2 => "ConnectQuery", 3 => "Shadow", 4 => "Disconnected",
                5 => "Idle", 6 => "Listen", 7 => "Reset", 8 => "Down", 9 => "Init", var x => x.ToString(),
            };
            WTSFreeMemory(buf);
        }

        // WTSINFOEXW { DWORD Level; WTSINFOEX_LEVEL1_W { ULONG SessionId; WTS_CONNECTSTATE_CLASS SessionState; LONG SessionFlags; ... } }
        // SessionFlags: 0 = WTS_SESSIONSTATE_LOCK, 1 = UNLOCK, -1 = unknown (Windows 8 / Server 2012 and later).
        if (WTSQuerySessionInformationW(IntPtr.Zero, sessionId, WTSSessionInfoEx, out buf, out var bytes) && buf != IntPtr.Zero)
        {
            if (bytes >= 16 && Marshal.ReadInt32(buf) == 1)
            {
                var flags = Marshal.ReadInt32(buf, 12);
                locked = flags switch { 0 => true, 1 => false, _ => null };
            }
            WTSFreeMemory(buf);
        }
        return (state, locked);
    }
}
