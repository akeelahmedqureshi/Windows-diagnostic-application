using MeshScreenDiag.Core.Models;

namespace MeshScreenDiag.Core.Catalogs;

public enum KnownSoftwareKind
{
    /// <summary>Known to use SetWindowDisplayAffinity or similar to hide windows from capture.</summary>
    CaptureProtection,
    /// <summary>Switches to its own desktop (CreateDesktop/SwitchDesktop) or the secure desktop.</summary>
    DesktopSwitch,
    /// <summary>Plays protected (DRM/HDCP) media.</summary>
    ProtectedMedia,
    /// <summary>Antivirus / EDR. Usually does not black out the screen, but may block or quarantine the agent.</summary>
    SecuritySuite,
    /// <summary>Data-loss-prevention / screen-watermark / anti-screenshot agents.</summary>
    DataLossPrevention,
    /// <summary>Other remote access tools (may install capture/privacy-mode drivers or compete for the display).</summary>
    RemoteAccess,
    /// <summary>Virtual / indirect / USB display drivers that GDI capture may not see.</summary>
    VirtualDisplay,
    /// <summary>Windows components that indicate a state (UAC prompt, lock screen, screen saver).</summary>
    WindowsState,
}

public sealed record KnownSoftware(
    string Pattern,
    string Product,
    KnownSoftwareKind Kind,
    string Explanation,
    bool PrefixMatch = false);

/// <summary>
/// Heuristic catalog of software that is known to be involved in "black screen in remote tools" cases.
/// Matching is by executable / service / driver base name, case-insensitive, with or without extension.
/// A match is a hint, not proof: the analysis engine combines it with live evidence
/// (display affinity, desktop switch, capture test, timing).
/// </summary>
public static class KnownSoftwareCatalog
{
    public static readonly IReadOnlyList<KnownSoftware> Entries = new List<KnownSoftware>
    {
        // --- Windows state indicators --------------------------------------------------------
        new("consent", "Windows UAC prompt", KnownSoftwareKind.WindowsState,
            "A UAC elevation prompt is showing on the Secure Desktop. Only capture code running as SYSTEM on the Winlogon desktop can see it; other capturers get a black or frozen image."),
        new("LogonUI", "Windows logon / lock screen UI", KnownSoftwareKind.WindowsState,
            "The lock screen, Ctrl+Alt+Del screen or credential prompt is active on the Winlogon desktop."),
        new("scrnsave.scr", "Windows screen saver", KnownSoftwareKind.WindowsState,
            "A screen saver runs on the separate 'Screen-saver' desktop."),
        new("mfpmp", "Windows Protected Media Path", KnownSoftwareKind.ProtectedMedia,
            "mfpmp.exe hosts the Protected Media Path used for DRM (PlayReady) playback. Protected video is rendered through a path capture APIs cannot read and appears black remotely."),

        // --- Applications with capture protection / own desktop ------------------------------
        new("SafeExamBrowser", "Safe Exam Browser", KnownSoftwareKind.DesktopSwitch,
            "Safe Exam Browser runs the exam on a separate, newly created desktop and blocks screen capture.", PrefixMatch: true),
        new("LockDownBrowser", "Respondus LockDown Browser", KnownSoftwareKind.CaptureProtection,
            "LockDown Browser blocks screen capture and remote-control tools while an exam is open.", PrefixMatch: true),
        new("Examplify", "ExamSoft Examplify", KnownSoftwareKind.CaptureProtection,
            "Exam software that blocks screen capture during secure exams."),
        new("KeePass", "KeePass Password Safe", KnownSoftwareKind.DesktopSwitch,
            "KeePass can ask for the master key on a secure desktop ('Enter master key on secure desktop'), which remote tools see as black."),
        new("Signal", "Signal Desktop", KnownSoftwareKind.CaptureProtection,
            "Signal's 'Screen security' option sets window display affinity so the window captures as black."),
        new("Zoom", "Zoom", KnownSoftwareKind.CaptureProtection,
            "Zoom can hide its windows from screen capture (e.g. during screen sharing / 'hide from capture' options)."),
        new("ms-teams", "Microsoft Teams", KnownSoftwareKind.CaptureProtection,
            "Teams Premium watermark / 'prevent screen capture' meeting options mark the meeting window as capture-protected."),
        new("wfica32", "Citrix Workspace (ICA session)", KnownSoftwareKind.CaptureProtection,
            "Citrix App Protection can block screen capture of published apps/desktops; the Citrix window captures as black."),
        new("CDViewer", "Citrix Workspace desktop viewer", KnownSoftwareKind.CaptureProtection,
            "Citrix App Protection can block screen capture of the virtual desktop window."),
        new("vmware-view", "VMware / Omnissa Horizon Client", KnownSoftwareKind.CaptureProtection,
            "Horizon 'screen-capture blocking' makes the remote desktop window capture as black."),
        new("horizon-client", "Omnissa Horizon Client", KnownSoftwareKind.CaptureProtection,
            "Horizon 'screen-capture blocking' makes the remote desktop window capture as black."),
        new("Netflix", "Netflix app", KnownSoftwareKind.ProtectedMedia,
            "Plays DRM-protected video; the video area is black in any screen capture."),
        new("1Password", "1Password", KnownSoftwareKind.CaptureProtection,
            "Password managers commonly exclude their windows from screen capture."),

        // --- Banking / secure browser protection ----------------------------------------------
        new("RapportService", "IBM Trusteer Rapport", KnownSoftwareKind.CaptureProtection,
            "Trusteer Rapport protects banking sessions and can block screen capture and input injection."),
        new("RapportMgmtService", "IBM Trusteer Rapport", KnownSoftwareKind.CaptureProtection,
            "Trusteer Rapport protects banking sessions and can block screen capture and input injection."),
        new("seccenter", "Bitdefender Safepay", KnownSoftwareKind.DesktopSwitch,
            "Bitdefender Safepay opens banking sites on an isolated desktop; remote tools see black or the old desktop."),
        new("bdagent", "Bitdefender", KnownSoftwareKind.SecuritySuite,
            "Bitdefender security suite. Its Safepay browser uses a separate desktop and it may flag remote-access agents."),
        new("avp", "Kaspersky", KnownSoftwareKind.SecuritySuite,
            "Kaspersky 'Safe Money' / Protected Browser blocks screen capture of banking pages; Kaspersky may also classify remote-admin agents as riskware."),
        new("avpui", "Kaspersky", KnownSoftwareKind.SecuritySuite,
            "Kaspersky security suite (see Safe Money / Protected Browser)."),
        new("ekrn", "ESET", KnownSoftwareKind.SecuritySuite,
            "ESET security. 'Banking & Payment protection' runs a secured browser that can block capture; ESET may flag remote-admin tools as potentially unsafe."),

        // --- Security suites / EDR ------------------------------------------------------------
        new("MsMpEng", "Microsoft Defender Antivirus", KnownSoftwareKind.SecuritySuite,
            "Microsoft Defender. Can detect MeshAgent as RemoteAccess / HackTool and block or quarantine it."),
        new("MsSense", "Microsoft Defender for Endpoint", KnownSoftwareKind.SecuritySuite,
            "Defender for Endpoint (EDR). Endpoint DLP policies can restrict screen capture of protected content."),
        new("CSFalconService", "CrowdStrike Falcon", KnownSoftwareKind.SecuritySuite,
            "CrowdStrike Falcon EDR. May block or contain remote-access agents by policy."),
        new("SentinelAgent", "SentinelOne", KnownSoftwareKind.SecuritySuite,
            "SentinelOne EDR. May block or contain remote-access agents by policy."),
        new("CylanceSvc", "BlackBerry Cylance", KnownSoftwareKind.SecuritySuite,
            "Cylance endpoint protection."),
        new("SophosHealth", "Sophos", KnownSoftwareKind.SecuritySuite,
            "Sophos endpoint protection."),
        new("SAVService", "Sophos Anti-Virus", KnownSoftwareKind.SecuritySuite,
            "Sophos endpoint protection."),
        new("ccSvcHst", "Norton / Symantec", KnownSoftwareKind.SecuritySuite,
            "Norton / Symantec security suite."),
        new("mcshield", "McAfee / Trellix", KnownSoftwareKind.SecuritySuite,
            "McAfee / Trellix endpoint security."),
        new("WRSA", "Webroot SecureAnywhere", KnownSoftwareKind.SecuritySuite,
            "Webroot 'Identity Shield' can block screen capture of protected applications and browsers."),
        new("AvastSvc", "Avast", KnownSoftwareKind.SecuritySuite, "Avast security suite (Bank Mode uses a separate desktop)."),
        new("AVGSvc", "AVG", KnownSoftwareKind.SecuritySuite, "AVG security suite."),
        new("MBAMService", "Malwarebytes", KnownSoftwareKind.SecuritySuite,
            "Malwarebytes. May flag remote-access agents as PUP/RiskWare."),
        new("RepMgr", "VMware Carbon Black", KnownSoftwareKind.SecuritySuite, "Carbon Black endpoint protection."),

        // --- DLP / anti-screenshot --------------------------------------------------------------
        new("edpa", "Symantec / Broadcom DLP Endpoint", KnownSoftwareKind.DataLossPrevention,
            "DLP endpoint agent. Some DLP policies block screen capture of sensitive applications."),
        new("fppsvc", "Forcepoint DLP", KnownSoftwareKind.DataLossPrevention,
            "Forcepoint DLP endpoint. Policies can block screen capture."),
        new("dgagent", "Digital Guardian", KnownSoftwareKind.DataLossPrevention,
            "Digital Guardian DLP agent. Policies can block screen capture."),

        // --- Other remote access tools ----------------------------------------------------------
        new("TeamViewer", "TeamViewer", KnownSoftwareKind.RemoteAccess,
            "TeamViewer. Its 'Show black screen' privacy mode installs a monitor driver that blanks the physical display.", PrefixMatch: true),
        new("AnyDesk", "AnyDesk", KnownSoftwareKind.RemoteAccess,
            "AnyDesk. Its privacy mode blanks the local screen during sessions."),
        new("rustdesk", "RustDesk", KnownSoftwareKind.RemoteAccess, "RustDesk remote access (privacy mode can blank the screen)."),
        new("ScreenConnect.ClientService", "ConnectWise ScreenConnect", KnownSoftwareKind.RemoteAccess,
            "ScreenConnect remote access (blank-screen / privacy option)."),
        new("remoting_host", "Chrome Remote Desktop", KnownSoftwareKind.RemoteAccess, "Chrome Remote Desktop host."),
        new("SRService", "Splashtop Streamer", KnownSoftwareKind.RemoteAccess, "Splashtop (blank-screen option)."),
        new("tvnserver", "TightVNC", KnownSoftwareKind.RemoteAccess, "TightVNC server (may install a mirror driver)."),
        new("winvnc", "VNC server", KnownSoftwareKind.RemoteAccess, "VNC server (may install a mirror driver)."),
        new("parsecd", "Parsec", KnownSoftwareKind.RemoteAccess, "Parsec (installs a virtual display driver)."),

        // --- Display drivers that affect capture ------------------------------------------------
        new("DisplayLinkManager", "DisplayLink USB graphics", KnownSoftwareKind.VirtualDisplay,
            "DisplayLink USB monitors are driven by a software/indirect display driver; some capture paths show them as black."),
        new("dlidusb", "DisplayLink USB graphics driver", KnownSoftwareKind.VirtualDisplay,
            "DisplayLink kernel driver.", PrefixMatch: true),
        new("IddCx", "Indirect Display driver framework", KnownSoftwareKind.VirtualDisplay,
            "An indirect (virtual) display driver is loaded."),
        new("parsecvusba", "Parsec virtual USB / display", KnownSoftwareKind.VirtualDisplay,
            "Parsec virtual display components."),
    };

    public static KnownSoftware? Match(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var n = System.IO.Path.GetFileName(name.Trim().Replace('\\', '/'));
        var baseName = StripExtension(n);
        foreach (var e in Entries)
        {
            var pattern = StripExtension(e.Pattern);
            if (baseName.Equals(pattern, StringComparison.OrdinalIgnoreCase) || n.Equals(e.Pattern, StringComparison.OrdinalIgnoreCase))
                return e;
            if (e.PrefixMatch && baseName.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
                return e;
        }
        // Screen savers: any *.scr executable.
        if (n.EndsWith(".scr", StringComparison.OrdinalIgnoreCase))
            return Entries.First(e => e.Pattern == "scrnsave.scr");
        return null;
    }

    public static CauseCategory CategoryOf(KnownSoftwareKind kind) => kind switch
    {
        KnownSoftwareKind.CaptureProtection => CauseCategory.ApplicationCaptureProtection,
        KnownSoftwareKind.DesktopSwitch => CauseCategory.SecureDesktop,
        KnownSoftwareKind.ProtectedMedia => CauseCategory.ProtectedContent,
        KnownSoftwareKind.SecuritySuite => CauseCategory.SecuritySoftware,
        KnownSoftwareKind.DataLossPrevention => CauseCategory.SecuritySoftware,
        KnownSoftwareKind.RemoteAccess => CauseCategory.GpuDisplay,
        KnownSoftwareKind.VirtualDisplay => CauseCategory.GpuDisplay,
        KnownSoftwareKind.WindowsState => CauseCategory.SecureDesktop,
        _ => CauseCategory.General,
    };

    /// <summary>Loaded-module names that hint at how a process renders. Keys are lower-case DLL names.</summary>
    public static readonly IReadOnlyDictionary<string, string> ModuleIndicators = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["d3d9.dll"] = "Direct3D 9",
        ["d3d11.dll"] = "Direct3D 11",
        ["d3d12.dll"] = "Direct3D 12",
        ["opengl32.dll"] = "OpenGL",
        ["vulkan-1.dll"] = "Vulkan",
        ["dcomp.dll"] = "DirectComposition",
        ["mfplat.dll"] = "Media Foundation (video playback)",
        ["windows.media.protection.playready.dll"] = "PlayReady DRM",
        ["widevinecdm.dll"] = "Widevine DRM",
        ["mfpmp.dll"] = "Protected Media Path",
        ["windows.graphics.capture.dll"] = "Windows.Graphics.Capture (screen capture)",
    };

    public static bool IsDrmIndicator(string indicator) =>
        indicator.Contains("DRM", StringComparison.OrdinalIgnoreCase) ||
        indicator.Contains("Protected Media", StringComparison.OrdinalIgnoreCase);

    public static bool IsGpuIndicator(string indicator) =>
        indicator.StartsWith("Direct3D", StringComparison.OrdinalIgnoreCase) ||
        indicator is "OpenGL" or "Vulkan";

    /// <summary>GPU adapter names that indicate a virtual / indirect / remote display.</summary>
    public static bool IsVirtualAdapter(string adapterName)
    {
        var n = adapterName.ToLowerInvariant();
        return n.Contains("displaylink") || n.Contains("basic display") || n.Contains("remote display") ||
               n.Contains("indirect") || n.Contains("virtual") || n.Contains("parsec") || n.Contains("idd") ||
               n.Contains("citrix") || n.Contains("vmware svga") || n.Contains("hyper-v video") ||
               n.Contains("mirror") || n.Contains("teamviewer") || n.Contains("spacedesk") || n.Contains("usb");
    }

    private static string StripExtension(string n)
    {
        var dot = n.LastIndexOf('.');
        return dot > 0 && n.Length - dot <= 4 ? n[..dot] : n;
    }
}
