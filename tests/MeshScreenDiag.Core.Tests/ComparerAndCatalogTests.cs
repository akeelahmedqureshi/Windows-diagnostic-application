using MeshScreenDiag.Core.Analysis;
using MeshScreenDiag.Core.Catalogs;
using MeshScreenDiag.Core.Models;
using static MeshScreenDiag.Core.Tests.Fixtures;

namespace MeshScreenDiag.Core.Tests;

public class SnapshotComparerTests
{
    [Fact]
    public void IdenticalSnapshots_HaveNoDifferences()
    {
        var diff = SnapshotComparer.Compare(Healthy(), Healthy(T0.AddSeconds(2)));
        Assert.Empty(diff.Items);
    }

    [Fact]
    public void DetectsTheChangesThatMatterForABlackScreen()
    {
        var before = Healthy();
        var after = Healthy(T0.AddSeconds(4), "After");
        AddProtectedApp(after, 4242, "SecurePortal.exe", WindowInfo.WDA_MONITOR);
        MakeCaptureBlack(after);
        after.Display!.InputDesktopName = "Winlogon";
        after.Mesh!.Processes.RemoveAll(p => p.Role == "KVM");
        after.Mesh.Processes.Add(new MeshAgentProcess { Pid = 1600, Name = "MeshAgent.exe", SessionId = 1, Role = "KVM" });
        after.LoadedDrivers.Add(new LoadedDriverInfo { Name = "protectdrv.sys" });
        after.Firewall!.Rules.Add(new FirewallRuleInfo { Name = "Block agent", Enabled = true, Direction = "Out", Action = "Block", Application = @"C:\Program Files\Mesh Agent\MeshAgent.exe" });
        after.Services.Add(new ServiceInfo { Name = "ProtectSvc", DisplayName = "Protect service", State = "Running", StartMode = "Manual" });

        var diff = SnapshotComparer.Compare(before, after);

        Assert.Contains(diff.Items, i => i.Area == "Process" && i.Change == DiffChange.Added && i.Pid == 4242);
        Assert.Contains(diff.Items, i => i.Area == "Window" && i.Severity == Severity.Critical && i.Description.Contains("Capture protection ON"));
        Assert.Contains(diff.Items, i => i.Area == "Capture" && i.Severity == Severity.Critical);
        Assert.Contains(diff.Items, i => i.Area == "Desktop" && i.Description.Contains("Default -> Winlogon"));
        Assert.Contains(diff.Items, i => i.Area == "MeshAgent" && i.Description.Contains("RESTARTED"));
        Assert.Contains(diff.Items, i => i.Area == "Driver" && i.Key == "protectdrv.sys");
        Assert.Contains(diff.Items, i => i.Area == "FirewallRule" && i.Severity == Severity.Critical);
        Assert.Contains(diff.Items, i => i.Area == "Service" && i.Change == DiffChange.Added);
    }

    [Fact]
    public void FastSections_SkipSlowAreas()
    {
        var before = Healthy();
        var after = Healthy(T0.AddSeconds(2));
        after.Services.Add(new ServiceInfo { Name = "New", State = "Running" });

        var diff = SnapshotComparer.Compare(before, after, SnapshotSections.Fast);

        Assert.DoesNotContain(diff.Items, i => i.Area == "Service");
    }

    [Fact]
    public void PidReuse_IsReportedAsExitAndStart()
    {
        var before = Healthy();
        before.Processes.Add(Proc(5555, "old.exe", 1, start: T0.AddMinutes(-5)));
        var after = Healthy(T0.AddSeconds(2));
        after.Processes.Add(Proc(5555, "new.exe", 1, start: T0.AddSeconds(1)));

        var diff = SnapshotComparer.Compare(before, after, SnapshotSections.Processes);

        Assert.Contains(diff.Items, i => i.Change == DiffChange.Removed && i.ProcessName == "old.exe");
        Assert.Contains(diff.Items, i => i.Change == DiffChange.Added && i.ProcessName == "new.exe");
    }

    [Fact]
    public void TimelineBuilder_CarriesProcessIdentity()
    {
        var before = Healthy();
        var after = Healthy(T0.AddSeconds(2));
        after.Processes.Add(Proc(9001, "app.exe", 1));

        var events = TimelineBuilder.FromDiff(SnapshotComparer.Compare(before, after)).ToList();

        var e = Assert.Single(events);
        Assert.Equal(9001, e.Pid);
        Assert.Equal(DiffChange.Added, e.Change);
        Assert.Equal(after.TimeUtc, e.TimeUtc);
    }
}

public class CatalogTests
{
    [Theory]
    [InlineData(@"C:\Program Files\SEB\SafeExamBrowser.Client.exe", "Safe Exam Browser")]
    [InlineData("consent.exe", "Windows UAC prompt")]
    [InlineData("MFPMP.EXE", "Windows Protected Media Path")]
    [InlineData("TeamViewer_Service.exe", "TeamViewer")]
    [InlineData("Ribbons.scr", "Windows screen saver")]
    [InlineData("ScreenConnect.ClientService.exe", "ConnectWise ScreenConnect")]
    public void KnownSoftware_Matches(string name, string product) =>
        Assert.Equal(product, KnownSoftwareCatalog.Match(name)?.Product);

    [Theory]
    [InlineData("notepad.exe")]
    [InlineData("zoomit.exe")]
    [InlineData("")]
    public void KnownSoftware_DoesNotOvermatch(string name) => Assert.Null(KnownSoftwareCatalog.Match(name));

    [Fact]
    public void PortCatalog_DescribesMeshAgentAndWellKnownPorts()
    {
        Assert.Contains("MeshCentral agent -> server", PortCatalog.Describe("TCP", 50123, 443, "ESTABLISHED", "MeshAgent.exe", true));
        Assert.StartsWith("Listening: Remote Desktop Protocol", PortCatalog.Describe("TCP", 3389, 0, "LISTEN", "svchost.exe", false));
        Assert.Contains("Dynamic RPC endpoint", PortCatalog.Describe("TCP", 49664, 0, "LISTEN", "lsass.exe", false));
        Assert.Contains("mDNS", PortCatalog.Describe("UDP", 5353, 0, "", "svchost.exe", false));
        Assert.Contains("Microsoft Edge", PortCatalog.Describe("TCP", 51000, 443, "ESTABLISHED", "msedge.exe", false));
    }

    [Theory]
    [InlineData(0x061100u, true, true)]   // enabled, up to date (typical Defender)
    [InlineData(0x060100u, false, true)]  // disabled
    [InlineData(0x061110u, true, false)]  // enabled, out of date
    [InlineData(0x041000u, true, true)]
    public void SecurityCenterStateDecoding(uint state, bool enabled, bool upToDate)
    {
        var (e, u) = SecurityProductInfo.DecodeProductState(state);
        Assert.Equal(enabled, e);
        Assert.Equal(upToDate, u);
    }

    [Fact]
    public void FirewallRuleParser_ParsesRegistryFormat()
    {
        var r = FirewallRuleParser.Parse(@"v2.31|Action=Block|Active=TRUE|Dir=Out|Protocol=6|Profile=Private|Profile=Public|RPort=443|App=C:\Program Files\Mesh Agent\MeshAgent.exe|Name=Block Mesh|RA4=203.0.113.10|");

        Assert.NotNull(r);
        Assert.Equal("Block", r!.Action);
        Assert.True(r.Enabled);
        Assert.Equal("Out", r.Direction);
        Assert.Equal("TCP", r.Protocol);
        Assert.Equal("Private,Public", r.Profiles);
        Assert.Equal("443", r.RemotePorts);
        Assert.Equal("203.0.113.10", r.RemoteAddresses);
        Assert.Equal("Block Mesh", r.Name);
        Assert.Null(FirewallRuleParser.Parse("garbage"));
    }

    [Fact]
    public void RectCoverage()
    {
        var screen = new RectI(0, 0, 1920, 1080);
        Assert.Equal(1.0, new RectI(-8, -8, 1928, 1088).CoverageOf(screen), 3);
        Assert.Equal(0.25, new RectI(0, 0, 960, 540).CoverageOf(screen), 3);
        Assert.Equal(0.0, new RectI(2000, 0, 2500, 500).CoverageOf(screen), 3);
    }
}
