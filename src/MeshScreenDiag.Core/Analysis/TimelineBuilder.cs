using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Core.Analysis;

/// <summary>Turns snapshot differences and event-log entries into timeline events.</summary>
public static class TimelineBuilder
{
    public static IEnumerable<TimelineEvent> FromDiff(SnapshotDiff diff) =>
        diff.Items.Select(i => new TimelineEvent
        {
            TimeUtc = diff.AfterUtc,
            Category = i.Area,
            Severity = i.Severity,
            Title = i.Description,
            Source = "Monitor",
            Pid = i.Pid,
            ProcessName = i.ProcessName,
            Change = i.Change,
        });

    public static TimelineEvent FromEventLog(EventLogEntryInfo e) => new()
    {
        TimeUtc = e.TimeUtc,
        Category = "EventLog",
        Severity = ClassifyEvent(e),
        Title = $"{ShortChannel(e.Channel)} {e.Provider} #{e.EventId} ({e.Level}): {FirstLine(e.Message, 180)}",
        Details = e.Message,
        Source = "EventLog",
    };

    /// <summary>Severity of an event-log entry from the black-screen investigation's point of view.</summary>
    public static Severity ClassifyEvent(EventLogEntryInfo e)
    {
        var msg = e.Message ?? "";
        if (msg.Contains("mesh", StringComparison.OrdinalIgnoreCase) && e.Level is "Error" or "Critical" or "Warning")
            return Severity.Critical;
        if (msg.Contains("mesh", StringComparison.OrdinalIgnoreCase))
            return Severity.High;

        var ch = e.Channel;
        if (ch.Contains("Defender", StringComparison.OrdinalIgnoreCase))
            return e.EventId is 1006 or 1007 or 1008 or 1015 or 1116 or 1117 or 1118 or 1119 ? Severity.High
                : e.EventId is 5001 or 5007 or 1121 or 1122 or 1125 or 1126 ? Severity.Medium : Severity.Low;
        if (ch.Contains("Firewall", StringComparison.OrdinalIgnoreCase))
            return Severity.Medium;
        if (ch.Contains("AppLocker", StringComparison.OrdinalIgnoreCase) || ch.Contains("CodeIntegrity", StringComparison.OrdinalIgnoreCase))
            return e.Level is "Error" or "Warning" ? Severity.Medium : Severity.Low;
        if (ch.Contains("TerminalServices", StringComparison.OrdinalIgnoreCase))
            return Severity.Medium;
        if (e.EventId == 4101 || e.Provider.Equals("Display", StringComparison.OrdinalIgnoreCase))
            return Severity.High;
        if (e.Provider.Contains("Service Control Manager", StringComparison.OrdinalIgnoreCase))
            return e.EventId is 7031 or 7034 or 7045 ? Severity.Medium : Severity.Info;
        if (ch.Equals("Security", StringComparison.OrdinalIgnoreCase))
            return e.EventId is 5152 or 5157 or 4946 or 4947 or 4948 or 5025 ? Severity.Medium : Severity.Info;

        return e.Level switch
        {
            "Critical" => Severity.High,
            "Error" => Severity.Medium,
            "Warning" => Severity.Low,
            _ => Severity.Info,
        };
    }

    private static string ShortChannel(string channel)
    {
        var idx = channel.IndexOf("Microsoft-Windows-", StringComparison.OrdinalIgnoreCase);
        var s = idx >= 0 ? channel[(idx + "Microsoft-Windows-".Length)..] : channel;
        return "[" + s + "]";
    }

    private static string FirstLine(string s, int max)
    {
        var line = s.Split('\n', 2)[0].Trim();
        return line.Length <= max ? line : line[..max] + "…";
    }
}
