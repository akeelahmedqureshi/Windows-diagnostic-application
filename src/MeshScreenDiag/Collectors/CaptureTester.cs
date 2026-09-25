using System.Runtime.InteropServices;
using MeshScreenDiag.Core.Models;
using static MeshScreenDiag.Native.NativeMethods;

namespace MeshScreenDiag.Collectors;

/// <summary>
/// Reproduces what the MeshAgent KVM sees: it copies the screen through GDI (BitBlt/StretchBlt from the
/// desktop DC, the same API family the Windows MeshAgent uses) into a small off-screen bitmap and measures
/// how black it is. Nothing is saved or sent anywhere; only the statistics are kept.
/// </summary>
internal static class CaptureTester
{
    private const int SampleWidth = 480;

    public static CaptureTestResult Run(IReadOnlyList<MonitorInfo> monitors, IReadOnlyList<WindowInfo> windows)
    {
        var result = new CaptureTestResult { TimeUtc = DateTime.UtcNow };
        var screenDc = GetDC(IntPtr.Zero);
        if (screenDc == IntPtr.Zero)
        {
            result.Error = $"GetDC(desktop) failed (Win32 error {Marshal.GetLastWin32Error()})";
            return result;
        }

        try
        {
            foreach (var m in monitors)
                result.Monitors.Add(CaptureRegion(screenDc, m.DeviceName + (m.IsPrimary ? " (primary)" : ""), m.Bounds));

            foreach (var w in windows.Where(w => w.IsCaptureProtected && !w.IsMinimized && !w.IsCloaked).Take(8))
                result.ProtectedWindows.Add(CaptureRegion(screenDc, $"{w.ProcessName} window 0x{w.Handle:X}", w.Bounds));
        }
        catch (Exception ex)
        {
            result.Error = ex.Message;
        }
        finally
        {
            ReleaseDC(IntPtr.Zero, screenDc);
        }
        return result;
    }

    private static unsafe CaptureRegionResult CaptureRegion(IntPtr screenDc, string name, RectI bounds)
    {
        var r = new CaptureRegionResult { Name = name, Bounds = bounds };
        if (bounds.Width <= 0 || bounds.Height <= 0)
        {
            r.Win32Error = 87; // ERROR_INVALID_PARAMETER
            return r;
        }

        var w = Math.Min(SampleWidth, bounds.Width);
        var h = Math.Max(1, (int)((long)bounds.Height * w / bounds.Width));

        var memDc = CreateCompatibleDC(screenDc);
        var bmi = new BITMAPINFO
        {
            bmiHeader = new BITMAPINFOHEADER
            {
                biSize = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
                biWidth = w,
                biHeight = -h, // top-down
                biPlanes = 1,
                biBitCount = 32,
                biCompression = 0, // BI_RGB
            },
        };
        var dib = CreateDIBSection(screenDc, ref bmi, DIB_RGB_COLORS, out var bits, IntPtr.Zero, 0);
        if (memDc == IntPtr.Zero || dib == IntPtr.Zero)
        {
            r.Win32Error = Marshal.GetLastWin32Error();
            if (dib != IntPtr.Zero) DeleteObject(dib);
            if (memDc != IntPtr.Zero) DeleteDC(memDc);
            return r;
        }

        var old = SelectObject(memDc, dib);
        try
        {
            SetStretchBltMode(memDc, COLORONCOLOR);
            // Plain SRCCOPY (no CAPTUREBLT) avoids cursor flicker on the client's screen.
            r.Succeeded = StretchBlt(memDc, 0, 0, w, h, screenDc, bounds.Left, bounds.Top, bounds.Width, bounds.Height, SRCCOPY);
            if (!r.Succeeded)
            {
                r.Win32Error = Marshal.GetLastWin32Error();
                return r;
            }
            GdiFlush();

            var px = (uint*)bits;
            var total = w * h;
            long black = 0;
            double lum = 0;
            var buckets = new bool[4096];
            var distinct = 0;
            for (var i = 0; i < total; i++)
            {
                var p = px[i];
                var b = (int)(p & 0xFF);
                var g = (int)((p >> 8) & 0xFF);
                var rr = (int)((p >> 16) & 0xFF);
                if (rr + g + b <= 30) black++;
                lum += 0.299 * rr + 0.587 * g + 0.114 * b;
                var q = ((rr >> 4) << 8) | ((g >> 4) << 4) | (b >> 4);
                if (!buckets[q])
                {
                    buckets[q] = true;
                    distinct++;
                }
            }
            r.BlackRatio = (double)black / total;
            r.MeanLuminance = lum / total;
            r.DistinctColors = distinct;
        }
        finally
        {
            SelectObject(memDc, old);
            DeleteObject(dib);
            DeleteDC(memDc);
        }
        return r;
    }
}
