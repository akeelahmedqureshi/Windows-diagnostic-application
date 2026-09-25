using System.Management;
using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Collectors;

/// <summary>Antivirus / firewall products registered with Windows Security Center, and Microsoft Defender status.</summary>
internal static class SecurityCollector
{
    public static List<SecurityProductInfo> GetProducts(List<string> errors)
    {
        var list = new List<SecurityProductInfo>();
        foreach (var (cls, kind) in new[] { ("AntiVirusProduct", "Antivirus"), ("AntiSpywareProduct", "Antispyware"), ("FirewallProduct", "Firewall") })
        {
            try
            {
                using var searcher = new ManagementObjectSearcher("root\\SecurityCenter2", $"SELECT displayName, productState, pathToSignedProductExe FROM {cls}");
                foreach (ManagementObject mo in searcher.Get())
                {
                    using (mo)
                    {
                        var state = Convert.ToUInt32(mo["productState"] ?? 0u);
                        var (enabled, upToDate) = SecurityProductInfo.DecodeProductState(state);
                        list.Add(new SecurityProductInfo
                        {
                            Kind = kind,
                            Name = mo["displayName"]?.ToString() ?? "",
                            ProductState = state,
                            Enabled = enabled,
                            UpToDate = upToDate,
                            ExecutablePath = mo["pathToSignedProductExe"]?.ToString(),
                        });
                    }
                }
            }
            catch (ManagementException ex) when (ex.ErrorCode == ManagementStatus.InvalidNamespace)
            {
                // Windows Server has no Security Center namespace.
                errors.Add("Windows Security Center is not available (normal on Windows Server)");
                break;
            }
            catch (Exception ex)
            {
                errors.Add($"Security Center {cls}: {ex.Message}");
            }
        }
        return list;
    }

    public static DefenderStatus GetDefender()
    {
        var s = new DefenderStatus();
        try
        {
            using var searcher = new ManagementObjectSearcher("root\\Microsoft\\Windows\\Defender",
                "SELECT AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IsTamperProtected, AMProductVersion FROM MSFT_MpComputerStatus");
            foreach (ManagementObject mo in searcher.Get())
            {
                using (mo)
                {
                    s.AntivirusEnabled = mo["AntivirusEnabled"] as bool?;
                    s.RealTimeProtectionEnabled = mo["RealTimeProtectionEnabled"] as bool?;
                    s.BehaviorMonitorEnabled = mo["BehaviorMonitorEnabled"] as bool?;
                    s.IsTamperProtected = mo["IsTamperProtected"] as bool?;
                    s.ProductVersion = mo["AMProductVersion"]?.ToString();
                }
            }
        }
        catch (Exception ex)
        {
            s.Error = "Defender status unavailable: " + ex.Message;
        }
        return s;
    }
}
