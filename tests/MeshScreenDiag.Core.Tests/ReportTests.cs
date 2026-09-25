using MeshScreenDiag.Core.Analysis;
using MeshScreenDiag.Core.Models;
using MeshScreenDiag.Core.Reporting;
using static MeshScreenDiag.Core.Tests.Fixtures;

namespace MeshScreenDiag.Core.Tests;

public class ReportTests
{
    private static DiagnosticReport SampleReport(bool redact = false)
    {
        var baseline = Healthy();
        var after = Healthy(T0.AddMinutes(1), "After");
        AddProtectedApp(after, 4242, "SecurePortal.exe", WindowInfo.WDA_MONITOR);
        MakeCaptureBlack(after);
        var marker = new BlackScreenMarker { TimeUtc = T0.AddMinutes(1), Note = "client opened <portal>" };
        var timeline = TimelineBuilder.FromDiff(SnapshotComparer.Compare(baseline, after)).ToList();
        var verdict = AnalysisEngine.Analyze(new AnalysisInput { Current = after, Baseline = baseline, Timeline = timeline, Markers = new[] { marker } });
        return new DiagnosticReport
        {
            ToolVersion = "1.0.0",
            GeneratedUtc = T0.AddMinutes(2),
            Verdict = verdict,
            Current = after,
            Baseline = baseline,
            After = after,
            Diff = SnapshotComparer.Compare(baseline, after),
            Timeline = timeline,
            Markers = new() { marker },
            TitlesRedacted = redact,
        };
    }

    [Fact]
    public void Html_ContainsVerdictSectionsAndEscapesInput()
    {
        var html = new HtmlReportBuilder(SampleReport()).Build();

        Assert.StartsWith("<!DOCTYPE html>", html);
        Assert.Contains("Application screen-capture protection", html);
        Assert.Contains("SecurePortal.exe", html);
        Assert.Contains("BLACK SCREEN MARKED", html);
        Assert.Contains("id=\"network\"", html);
        Assert.Contains("client opened &lt;portal&gt;", html);
        Assert.DoesNotContain("<portal>", html);
        Assert.Contains("Secure Client Portal", html);
    }

    [Fact]
    public void Html_RedactsWindowTitles()
    {
        var html = new HtmlReportBuilder(SampleReport(redact: true)).Build();

        Assert.DoesNotContain("Secure Client Portal", html);
        Assert.Contains("[redacted]", html);
    }

    [Fact]
    public void Html_AutoRefresh_IsOptional()
    {
        var r = SampleReport();
        Assert.DoesNotContain("http-equiv=\"refresh\"", new HtmlReportBuilder(r).Build());
        Assert.Contains("http-equiv=\"refresh\" content=\"5\"", new HtmlReportBuilder(r).Build(autoRefreshSeconds: 5));
    }

    [Fact]
    public void Json_RoundTrips()
    {
        var r = SampleReport();
        var back = DiagnosticReport.FromJson(r.ToJson());

        Assert.NotNull(back);
        Assert.Equal(r.Verdict.Headline, back!.Verdict.Headline);
        Assert.Equal(r.Current.Windows.Count, back.Current.Windows.Count);
        Assert.Equal(WindowInfo.WDA_MONITOR, back.Current.Windows.Last().DisplayAffinity);
        Assert.Contains("\"ApplicationCaptureProtection\"", r.ToJson());
    }

    [Fact]
    public void TextSummary_IsShortAndActionable()
    {
        var text = TextSummaryBuilder.Build(SampleReport());

        Assert.Contains("VERDICT: Most likely cause: Application screen-capture protection", text);
        Assert.Contains("CONNECTION vs CAPTURE: CAPTURE", text);
        Assert.Contains("KEY FINDINGS", text);
    }
}

public class SampleReportWriter
{
    /// <summary>Writes a sample report for visual review when MESHSCREENDIAG_SAMPLE_OUT points to a folder.</summary>
    [Fact]
    public void WriteSampleReportWhenRequested()
    {
        var dir = Environment.GetEnvironmentVariable("MESHSCREENDIAG_SAMPLE_OUT");
        if (string.IsNullOrEmpty(dir)) return;
        var baseline = Healthy();
        var after = Healthy(T0.AddMinutes(1), "After (black screen marked)");
        AddProtectedApp(after, 4242, "SecurePortal.exe", WindowInfo.WDA_MONITOR);
        MakeCaptureBlack(after);
        var marker = new BlackScreenMarker { TimeUtc = T0.AddMinutes(1).AddSeconds(3), Note = "client opened the banking portal" };
        var timeline = TimelineBuilder.FromDiff(SnapshotComparer.Compare(baseline, after)).ToList();
        var verdict = AnalysisEngine.Analyze(new AnalysisInput { Current = after, Baseline = baseline, Timeline = timeline, Markers = new[] { marker } });
        var report = new DiagnosticReport
        {
            ToolVersion = "1.0.0", GeneratedUtc = T0.AddMinutes(2), Verdict = verdict, Current = after, Baseline = baseline, After = after,
            Diff = SnapshotComparer.Compare(baseline, after), Timeline = timeline, Markers = new() { marker },
        };
        Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "sample-report.html"), new HtmlReportBuilder(report).Build());
        File.WriteAllText(Path.Combine(dir, "sample-summary.txt"), TextSummaryBuilder.Build(report));
    }
}
