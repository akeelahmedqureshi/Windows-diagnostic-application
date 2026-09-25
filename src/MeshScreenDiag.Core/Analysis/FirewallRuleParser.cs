using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Core.Analysis;

/// <summary>
/// Parses the rule strings Windows Firewall stores in the registry, e.g.
/// <c>v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Private|LPort=443|App=C:\x.exe|Name=Example|</c>.
/// Used as a fallback when the COM firewall API is unavailable.
/// </summary>
public static class FirewallRuleParser
{
    public static FirewallRuleInfo? Parse(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || !raw.StartsWith("v", StringComparison.OrdinalIgnoreCase)) return null;

        var rule = new FirewallRuleInfo { Enabled = false, Direction = "", Action = "", Protocol = "Any", Profiles = "All" };
        var profiles = new List<string>();
        var ra = new List<string>();
        var lports = new List<string>();
        var rports = new List<string>();

        foreach (var part in raw.Split('|'))
        {
            var eq = part.IndexOf('=');
            if (eq <= 0) continue;
            var key = part[..eq];
            var val = part[(eq + 1)..];
            switch (key)
            {
                case "Action": rule.Action = val; break;
                case "Active": rule.Enabled = val.Equals("TRUE", StringComparison.OrdinalIgnoreCase); break;
                case "Dir": rule.Direction = val; break;
                case "Protocol":
                    rule.Protocol = val switch { "6" => "TCP", "17" => "UDP", "1" => "ICMPv4", "58" => "ICMPv6", _ => val };
                    break;
                case "Profile": profiles.Add(val); break;
                case "LPort": lports.Add(val); break;
                case "RPort": rports.Add(val); break;
                case "RA4":
                case "RA6": ra.Add(val); break;
                case "App": rule.Application = val; break;
                case "Svc": rule.Service = val; break;
                case "Name": rule.Name = val; break;
                case "EmbedCtxt": rule.Grouping = val; break;
            }
        }

        if (profiles.Count > 0) rule.Profiles = string.Join(",", profiles);
        if (lports.Count > 0) rule.LocalPorts = string.Join(",", lports);
        if (rports.Count > 0) rule.RemotePorts = string.Join(",", rports);
        if (ra.Count > 0) rule.RemoteAddresses = string.Join(",", ra);
        return rule;
    }
}
