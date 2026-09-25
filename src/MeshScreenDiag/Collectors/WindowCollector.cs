using System.Runtime.InteropServices;
using System.Text;
using MeshScreenDiag.Core.Models;
using static MeshScreenDiag.Native.NativeMethods;

namespace MeshScreenDiag.Collectors;

/// <summary>
/// Enumerates visible top-level windows and reads each window's display affinity — the single most
/// common reason for "remote screen black, mouse still works": an application calling
/// SetWindowDisplayAffinity(WDA_MONITOR / WDA_EXCLUDEFROMCAPTURE). GetWindowDisplayAffinity can be
/// called for windows of any process.
/// </summary>
internal static class WindowCollector
{
    public static List<WindowInfo> Collect(IReadOnlyList<MonitorInfo> monitors, IReadOnlyDictionary<int, string> processNames)
    {
        var result = new List<WindowInfo>();
        var foreground = GetForegroundWindow();
        var ownPid = Environment.ProcessId;
        var title = new StringBuilder(512);
        var cls = new StringBuilder(256);

        EnumWindows((hWnd, _) =>
        {
            if (!IsWindowVisible(hWnd)) return true;
            GetWindowThreadProcessId(hWnd, out var upid);
            var pid = (int)upid;
            if (pid == ownPid) return true;

            if (!TryGetBounds(hWnd, out var rect) || rect.Width <= 0 || rect.Height <= 0) return true;

            GetWindowDisplayAffinity(hWnd, out var affinity);
            var cloaked = DwmGetWindowAttribute(hWnd, DWMWA_CLOAKED, out int cloakVal, sizeof(int)) == 0 && cloakVal != 0;
            var ex = GetWindowLongPtr(hWnd, GWL_EXSTYLE).ToInt64();

            // Skip tiny invisible helper windows unless they carry a display affinity (always interesting).
            if (affinity == 0 && (rect.Width < 8 || rect.Height < 8)) return true;

            title.Clear();
            var len = GetWindowTextLengthW(hWnd);
            if (len > 0)
            {
                title.EnsureCapacity(len + 1);
                GetWindowTextW(hWnd, title, Math.Min(len + 1, 1024));
            }
            cls.Clear();
            GetClassNameW(hWnd, cls, cls.Capacity);

            var w = new WindowInfo
            {
                Handle = hWnd.ToInt64(),
                Pid = pid,
                ProcessName = processNames.TryGetValue(pid, out var n) ? n : $"PID {pid}",
                Title = title.ToString(),
                ClassName = cls.ToString(),
                Bounds = rect,
                DisplayAffinity = affinity,
                IsForeground = hWnd == foreground,
                IsTopMost = (ex & WS_EX_TOPMOST) != 0,
                IsLayered = (ex & WS_EX_LAYERED) != 0,
                IsClickThrough = (ex & WS_EX_TRANSPARENT) != 0,
                IsCloaked = cloaked,
                IsMinimized = IsIconic(hWnd),
                IsHung = IsHungAppWindow(hWnd),
            };

            foreach (var m in monitors)
            {
                var cov = rect.CoverageOf(m.Bounds);
                if (cov > w.MaxMonitorCoverage)
                {
                    w.MaxMonitorCoverage = cov;
                    w.MonitorDevice = m.DeviceName;
                }
            }

            // Cloaked windows (other virtual desktops, suspended UWP apps) are not on screen; keep them only if protected.
            if (!cloaked || affinity != 0) result.Add(w);
            return true;
        }, IntPtr.Zero);

        return result;
    }

    private static bool TryGetBounds(IntPtr hWnd, out RectI rect)
    {
        // Extended frame bounds exclude the invisible resize borders, giving accurate "full screen" detection.
        if (DwmGetWindowAttribute(hWnd, DWMWA_EXTENDED_FRAME_BOUNDS, out RECT r, Marshal.SizeOf<RECT>()) != 0 &&
            !GetWindowRect(hWnd, out r))
        {
            rect = new RectI();
            return false;
        }
        rect = new RectI(r.Left, r.Top, r.Right, r.Bottom);
        return true;
    }
}
