using System.Text.Json;
using System.Text.Json.Serialization;
using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Core.Reporting;

/// <summary>Everything that goes into a shareable report.</summary>
public sealed class DiagnosticReport
{
    public string ToolVersion { get; set; } = "";
    public DateTime GeneratedUtc { get; set; }
    public DiagnosticVerdict Verdict { get; set; } = new();
    public SystemSnapshot Current { get; set; } = new();
    public SystemSnapshot? Baseline { get; set; }
    public SystemSnapshot? After { get; set; }
    public SnapshotDiff? Diff { get; set; }
    public List<TimelineEvent> Timeline { get; set; } = new();
    public List<BlackScreenMarker> Markers { get; set; } = new();
    public List<EventLogEntryInfo> Events { get; set; } = new();
    public bool TitlesRedacted { get; set; }
    public string? TechnicianNotes { get; set; }
    public TimeSpan CorrelationWindow { get; set; } = TimeSpan.FromMinutes(2);

    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, JsonOptions);

    public static DiagnosticReport? FromJson(string json) => JsonSerializer.Deserialize<DiagnosticReport>(json, JsonOptions);
}
