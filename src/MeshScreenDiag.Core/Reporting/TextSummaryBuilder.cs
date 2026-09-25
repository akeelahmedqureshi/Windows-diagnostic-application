using System.Text;
using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Core.Reporting;

/// <summary>Short plain-text summary suitable for pasting into a ticket, chat or e-mail.</summary>
public static class TextSummaryBuilder
{
    public static string Build(DiagnosticReport r, int maxFindings = 8)
    {
        var c = r.Current;
        var v = r.Verdict;
        var sb = new StringBuilder();
        sb.AppendLine($"MeshCentral screen diagnostic — {c.MachineName} ({c.UserName}) — {r.GeneratedUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine(new string('=', 78));
        sb.AppendLine("VERDICT: " + v.Headline);
        sb.AppendLine("CONNECTION vs CAPTURE: " + v.ConnectionVsCapture);
        sb.AppendLine("  " + v.ConnectionVsCaptureDetail);
        sb.AppendLine();
        sb.AppendLine($"MeshCentral agent : {c.Mesh?.Health ?? "n/a"}  (server {c.Mesh?.ServerUrl ?? "?"}, {c.Mesh?.EstablishedCount ?? 0} established, KVM {(c.Mesh?.KvmActive == true ? "running" : "not running")})");
        sb.AppendLine($"Capture test      : {c.Capture?.Summary ?? "n/a"}");
        sb.AppendLine($"Input desktop     : {(c.Display == null ? "n/a" : c.Display.InputDesktopAccessible ? c.Display.InputDesktopName : "secure desktop (inaccessible)")}");
        sb.AppendLine($"Protected windows : {c.Windows.Count(w => w.IsCaptureProtected && !w.IsMinimized)}");
        if (r.Markers.Count > 0)
            sb.AppendLine($"Black-screen marks: {string.Join(", ", r.Markers.Select(m => m.TimeUtc.ToLocalTime().ToString("HH:mm:ss")))}");
        sb.AppendLine();

        var important = v.Findings.Where(f => f.Severity >= Severity.Medium).Take(maxFindings).ToList();
        if (important.Count > 0)
        {
            sb.AppendLine("KEY FINDINGS");
            foreach (var f in important)
            {
                sb.AppendLine($"- [{f.Severity}] {f.Title}");
                foreach (var e in f.Evidence.Take(4)) sb.AppendLine($"    · {e}");
                if (!string.IsNullOrEmpty(f.Recommendation)) sb.AppendLine($"    → {f.Recommendation}");
            }
            sb.AppendLine();
        }

        if (v.SuspectApplications.Count > 0)
        {
            sb.AppendLine("APPLICATIONS STARTED AROUND THE BLACK SCREEN");
            foreach (var s in v.SuspectApplications.Take(10)) sb.AppendLine("- " + s);
        }
        return sb.ToString();
    }
}
