using System.Diagnostics.Eventing.Reader;
using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Collectors;

/// <summary>
/// Incrementally reads the event-log channels that matter for a black remote screen: display driver
/// resets, crashes, service changes, Defender detections, firewall changes/drops, session changes,
/// AppLocker / Code Integrity blocks. Each channel keeps its own "last record" bookmark.
/// </summary>
internal sealed class EventLogCollector
{
    private sealed record ChannelSpec(string Channel, string Filter, bool AdminOnly = false, int MaxPerPoll = 300);

    private static readonly ChannelSpec[] Specs =
    {
        new("System", "(Level=1 or Level=2 or Level=3 or EventID=7045 or EventID=7040 or EventID=4101)"),
        new("Application", "(Level=1 or Level=2 or EventID=1000 or EventID=1001 or EventID=1002)"),
        new("Security", "(EventID=4688 or EventID=5152 or EventID=5157 or EventID=4946 or EventID=4947 or EventID=4948 or EventID=4950 or EventID=5025 or EventID=5031 or EventID=4800 or EventID=4801)", AdminOnly: true, MaxPerPoll: 500),
        new("Microsoft-Windows-Windows Defender/Operational", "(EventID=1006 or EventID=1007 or EventID=1008 or EventID=1015 or EventID=1116 or EventID=1117 or EventID=1118 or EventID=1119 or EventID=1121 or EventID=1122 or EventID=1125 or EventID=1126 or EventID=5001 or EventID=5004 or EventID=5007 or EventID=5010 or EventID=5012)"),
        new("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", ""),
        new("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "(EventID=21 or EventID=23 or EventID=24 or EventID=25 or EventID=39 or EventID=40 or EventID=41 or EventID=42)"),
        new("Microsoft-Windows-CodeIntegrity/Operational", "(Level=1 or Level=2 or Level=3)"),
        new("Microsoft-Windows-AppLocker/EXE and DLL", "(EventID=8003 or EventID=8004 or EventID=8006 or EventID=8007)"),
    };

    private readonly Dictionary<string, long> _lastRecord = new();
    private readonly HashSet<string> _reportedErrors = new();
    private DateTime _since;

    public EventLogCollector(TimeSpan lookback)
    {
        _since = DateTime.UtcNow - lookback;
    }

    /// <summary>Returns entries newer than the previous call (the first call returns the look-back window).</summary>
    public List<EventLogEntryInfo> Poll(bool elevated, List<string> errors)
    {
        var result = new List<EventLogEntryInfo>();
        var pollStart = DateTime.UtcNow;
        foreach (var spec in Specs)
        {
            if (spec.AdminOnly && !elevated)
            {
                ReportOnce(errors, $"{spec.Channel} log: requires administrator rights");
                continue;
            }
            try
            {
                ReadChannel(spec, result);
            }
            catch (EventLogNotFoundException)
            {
                // Channel does not exist on this edition (e.g. AppLocker on Home) — ignore.
            }
            catch (UnauthorizedAccessException)
            {
                ReportOnce(errors, $"{spec.Channel} log: access denied");
            }
            catch (Exception ex)
            {
                ReportOnce(errors, $"{spec.Channel} log: {ex.Message}");
            }
        }
        // Small overlap guards against clock skew between record timestamps and our clock; record IDs de-duplicate.
        _since = pollStart - TimeSpan.FromSeconds(10);
        return result;
    }

    private void ReadChannel(ChannelSpec spec, List<EventLogEntryInfo> result)
    {
        var time = $"TimeCreated[@SystemTime>='{_since:yyyy-MM-ddTHH:mm:ss.fffZ}']";
        var xpath = string.IsNullOrEmpty(spec.Filter)
            ? $"*[System[{time}]]"
            : $"*[System[{spec.Filter} and {time}]]";
        var query = new EventLogQuery(spec.Channel, PathType.LogName, xpath) { ReverseDirection = true };
        _lastRecord.TryGetValue(spec.Channel, out var last);

        var batch = new List<EventLogEntryInfo>();
        using var reader = new EventLogReader(query);
        for (var i = 0; i < spec.MaxPerPoll; i++)
        {
            using var rec = reader.ReadEvent();
            if (rec == null) break;
            var id = rec.RecordId ?? 0;
            if (id <= last) break; // reading newest-first: everything older was already seen
            string message;
            try
            {
                message = rec.FormatDescription() ?? "";
            }
            catch
            {
                message = "";
            }
            if (string.IsNullOrEmpty(message))
                message = string.Join("; ", rec.Properties.Select(p => p.Value?.ToString()).Where(v => !string.IsNullOrEmpty(v)));
            if (message.Length > 2000) message = message[..2000] + "…";

            batch.Add(new EventLogEntryInfo
            {
                TimeUtc = rec.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
                Channel = spec.Channel,
                Provider = rec.ProviderName ?? "",
                EventId = rec.Id,
                Level = LevelName(rec.Level),
                Message = message.Trim(),
                RecordId = id,
            });
        }

        if (batch.Count > 0)
        {
            _lastRecord[spec.Channel] = Math.Max(last, batch.Max(b => b.RecordId));
            batch.Reverse(); // chronological
            result.AddRange(batch);
        }
    }

    private static string LevelName(byte? level) => level switch
    {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        0 => "Information", // Security audit events use level 0
        5 => "Verbose",
        _ => level?.ToString() ?? "",
    };

    private void ReportOnce(List<string> errors, string message)
    {
        if (_reportedErrors.Add(message)) errors.Add(message);
    }
}
