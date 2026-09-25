namespace MeshScreenDiag.Core.Models;

public sealed class TimelineEvent
{
    public DateTime TimeUtc { get; set; }
    public string Category { get; set; } = "";
    public Severity Severity { get; set; }
    public string Title { get; set; } = "";
    public string? Details { get; set; }
    /// <summary>Monitor, EventLog, User, Session, ...</summary>
    public string Source { get; set; } = "Monitor";

    /// <summary>Process the event is about, when there is one (used for correlation).</summary>
    public int? Pid { get; set; }
    public string? ProcessName { get; set; }

    /// <summary>For events derived from a snapshot diff: the change that produced it.</summary>
    public DiffChange? Change { get; set; }

    public override string ToString() => $"{TimeUtc.ToLocalTime():HH:mm:ss} [{Severity}] {Category}: {Title}";
}

/// <summary>A point in time the technician (or the auto-detector) flagged as "the screen went black here".</summary>
public sealed class BlackScreenMarker
{
    public DateTime TimeUtc { get; set; }
    public string Note { get; set; } = "";
    public bool Automatic { get; set; }
}

public sealed class DiffItem
{
    /// <summary>Process, Window, Service, Driver, Connection, FirewallRule, FirewallProfile, SecurityProduct, Display, Capture, MeshAgent, Desktop, Session.</summary>
    public string Area { get; set; } = "";
    public DiffChange Change { get; set; }
    public string Key { get; set; } = "";
    public string Description { get; set; } = "";
    public Severity Severity { get; set; }
    public int? Pid { get; set; }
    public string? ProcessName { get; set; }

    public override string ToString() => $"[{Area}] {Change}: {Description}";
}

public sealed class SnapshotDiff
{
    public DateTime BeforeUtc { get; set; }
    public DateTime AfterUtc { get; set; }
    public string BeforeLabel { get; set; } = "";
    public string AfterLabel { get; set; } = "";
    public List<DiffItem> Items { get; set; } = new();

    public IEnumerable<IGrouping<string, DiffItem>> ByArea() =>
        Items.OrderByDescending(i => i.Severity).GroupBy(i => i.Area);
}

public sealed class Finding
{
    public string Id { get; set; } = "";
    public CauseCategory Category { get; set; }
    public Severity Severity { get; set; }
    public string Title { get; set; } = "";
    public string Explanation { get; set; } = "";
    public List<string> Evidence { get; set; } = new();
    public string Recommendation { get; set; } = "";

    /// <summary>How strongly this finding points at its category as the root cause of the black screen (0..100).</summary>
    public int Weight { get; set; }
}

public sealed class CategoryScore
{
    public CauseCategory Category { get; set; }
    public int Score { get; set; }
    public string Label { get; set; } = "";
}

public sealed class DiagnosticVerdict
{
    public DateTime TimeUtc { get; set; }
    public string Headline { get; set; } = "";
    public CauseCategory? PrimaryCause { get; set; }
    public string PrimaryCauseLabel { get; set; } = "";

    /// <summary>"Connection" vs "Capture" determination with a human-readable explanation.</summary>
    public string ConnectionVsCapture { get; set; } = "";
    public string ConnectionVsCaptureDetail { get; set; } = "";

    public List<Finding> Findings { get; set; } = new();
    public List<CategoryScore> Scores { get; set; } = new();

    /// <summary>Processes that started close to the black-screen moment (the prime suspects).</summary>
    public List<string> SuspectApplications { get; set; } = new();
}

public static class CategoryLabels
{
    public static string Of(CauseCategory c) => c switch
    {
        CauseCategory.ApplicationCaptureProtection => "Application screen-capture protection",
        CauseCategory.SecureDesktop => "Secure / alternate desktop switch",
        CauseCategory.ProtectedContent => "DRM / protected content",
        CauseCategory.GpuDisplay => "GPU / display rendering",
        CauseCategory.SecuritySoftware => "Security software (AV / EDR / DLP / banking protection)",
        CauseCategory.FirewallNetwork => "Firewall / network",
        CauseCategory.MeshCentralAgent => "MeshCentral agent",
        CauseCategory.SessionState => "Windows session state",
        _ => "General",
    };
}
