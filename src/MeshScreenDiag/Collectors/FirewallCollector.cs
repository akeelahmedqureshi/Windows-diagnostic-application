using System.Collections;
using System.Reflection;
using MeshScreenDiag.Core.Analysis;
using MeshScreenDiag.Core.Models;
using Microsoft.Win32;

namespace MeshScreenDiag.Collectors;

/// <summary>
/// Windows Firewall profiles and rules through the HNetCfg.FwPolicy2 COM API (read-only). Falls back to the
/// rule strings stored in the registry when COM is unavailable.
/// </summary>
internal static class FirewallCollector
{
    private static readonly (int id, string name)[] ProfileIds = { (1, "Domain"), (2, "Private"), (4, "Public") };

    public static FirewallState Collect()
    {
        try
        {
            return CollectViaCom();
        }
        catch (Exception ex)
        {
            var state = CollectViaRegistry();
            state.Error = $"Firewall COM API unavailable ({ex.Message}); rules read from the registry instead.";
            return state;
        }
    }

    private static FirewallState CollectViaCom()
    {
        var state = new FirewallState();
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        var policy = Activator.CreateInstance(type)!;
        try
        {
            var current = Convert.ToInt32(Get(policy, "CurrentProfileTypes"));
            foreach (var (id, name) in ProfileIds)
            {
                state.Profiles.Add(new FirewallProfileInfo
                {
                    Name = name,
                    IsActive = (current & id) != 0,
                    Enabled = Convert.ToBoolean(Get(policy, "FirewallEnabled", id)),
                    DefaultInboundAction = ActionName(Convert.ToInt32(Get(policy, "DefaultInboundAction", id))),
                    DefaultOutboundAction = ActionName(Convert.ToInt32(Get(policy, "DefaultOutboundAction", id))),
                    BlockAllInbound = Convert.ToBoolean(Get(policy, "BlockAllInboundTraffic", id)),
                });
            }

            var rules = Get(policy, "Rules");
            if (rules is IEnumerable enumerable)
            {
                foreach (var rule in enumerable)
                {
                    if (rule == null) continue;
                    try
                    {
                        state.Rules.Add(new FirewallRuleInfo
                        {
                            Name = Get(rule, "Name")?.ToString() ?? "",
                            Enabled = Convert.ToBoolean(Get(rule, "Enabled")),
                            Direction = Convert.ToInt32(Get(rule, "Direction")) == 1 ? "In" : "Out",
                            Action = ActionName(Convert.ToInt32(Get(rule, "Action"))),
                            Protocol = ProtocolName(Convert.ToInt32(Get(rule, "Protocol"))),
                            LocalPorts = Get(rule, "LocalPorts")?.ToString(),
                            RemotePorts = Get(rule, "RemotePorts")?.ToString(),
                            RemoteAddresses = Get(rule, "RemoteAddresses")?.ToString(),
                            Application = Get(rule, "ApplicationName")?.ToString(),
                            Service = Get(rule, "ServiceName")?.ToString(),
                            Profiles = ProfilesName(Convert.ToInt32(Get(rule, "Profiles"))),
                            Grouping = Get(rule, "Grouping")?.ToString(),
                        });
                    }
                    finally
                    {
                        if (System.Runtime.InteropServices.Marshal.IsComObject(rule))
                            System.Runtime.InteropServices.Marshal.ReleaseComObject(rule);
                    }
                }
            }
            if (rules != null && System.Runtime.InteropServices.Marshal.IsComObject(rules))
                System.Runtime.InteropServices.Marshal.ReleaseComObject(rules);
        }
        finally
        {
            System.Runtime.InteropServices.Marshal.ReleaseComObject(policy);
        }
        return state;
    }

    private static object? Get(object com, string property, params object[] args) =>
        com.GetType().InvokeMember(property, BindingFlags.GetProperty, null, com, args.Length == 0 ? null : args);

    private static FirewallState CollectViaRegistry()
    {
        var state = new FirewallState();
        void ReadProfile(string key, string name)
        {
            using var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{key}");
            if (k == null) return;
            state.Profiles.Add(new FirewallProfileInfo
            {
                Name = name,
                Enabled = k.GetValue("EnableFirewall") is int e && e != 0,
                DefaultInboundAction = k.GetValue("DefaultInboundAction") is int i && i == 0 ? "Allow" : "Block",
                DefaultOutboundAction = k.GetValue("DefaultOutboundAction") is int o && o == 1 ? "Block" : "Allow",
                BlockAllInbound = k.GetValue("DoNotAllowExceptions") is int d && d != 0,
            });
        }
        ReadProfile("DomainProfile", "Domain");
        ReadProfile("StandardProfile", "Private");
        ReadProfile("PublicProfile", "Public");

        foreach (var path in new[]
                 {
                     @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                     @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules",
                 })
        {
            using var k = Registry.LocalMachine.OpenSubKey(path);
            if (k == null) continue;
            foreach (var valueName in k.GetValueNames())
                if (k.GetValue(valueName) is string s && FirewallRuleParser.Parse(s) is { } rule)
                    state.Rules.Add(rule);
        }
        return state;
    }

    private static string ActionName(int a) => a switch { 0 => "Block", 1 => "Allow", _ => a.ToString() };

    private static string ProtocolName(int p) => p switch { 6 => "TCP", 17 => "UDP", 1 => "ICMPv4", 58 => "ICMPv6", 256 => "Any", _ => p.ToString() };

    private static string ProfilesName(int mask)
    {
        if (mask == 0x7FFFFFFF || mask == 7) return "All";
        var names = ProfileIds.Where(p => (mask & p.id) != 0).Select(p => p.name).ToList();
        return names.Count == 0 ? mask.ToString() : string.Join(",", names);
    }
}
