namespace MeshScreenDiag.Core.Models;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>
/// The root-cause buckets the tool tries to decide between. Every finding is filed
/// under exactly one of these so the verdict can say "most likely: X".
/// </summary>
public enum CauseCategory
{
    /// <summary>An application protects its own window from capture (SetWindowDisplayAffinity).</summary>
    ApplicationCaptureProtection,
    /// <summary>The input desktop switched away from "Default" (UAC, lock screen, Safepay, SEB, ...).</summary>
    SecureDesktop,
    /// <summary>DRM / Protected Media Path / HDCP protected video.</summary>
    ProtectedContent,
    /// <summary>Exclusive full-screen DirectX, overlays, GPU driver resets, display topology changes.</summary>
    GpuDisplay,
    /// <summary>Antivirus, EDR, DLP, banking protection or other security software.</summary>
    SecuritySoftware,
    /// <summary>Firewall rules, blocked traffic, network path.</summary>
    FirewallNetwork,
    /// <summary>The MeshCentral agent itself (service stopped, KVM process crashed, disconnected).</summary>
    MeshCentralAgent,
    /// <summary>Windows session state (locked, disconnected, different console session).</summary>
    SessionState,
    /// <summary>Informational / not attributable.</summary>
    General,
}

public enum DiffChange
{
    Added,
    Removed,
    Changed,
}
