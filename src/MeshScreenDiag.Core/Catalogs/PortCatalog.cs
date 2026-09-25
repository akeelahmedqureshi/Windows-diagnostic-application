namespace MeshScreenDiag.Core.Catalogs;

/// <summary>
/// Human-readable purpose for ports and connections. Purpose is derived from (in order):
/// the owning process, the well-known remote port, the well-known local port, and the port range.
/// </summary>
public static class PortCatalog
{
    private static readonly Dictionary<int, string> Tcp = new()
    {
        [20] = "FTP data",
        [21] = "FTP control",
        [22] = "SSH / SFTP",
        [23] = "Telnet",
        [25] = "SMTP (mail submission/relay)",
        [53] = "DNS (zone transfer / large responses)",
        [80] = "HTTP (web; MeshCentral HTTP / redirect port by default)",
        [88] = "Kerberos authentication",
        [110] = "POP3 mail",
        [135] = "Microsoft RPC endpoint mapper (DCOM/WMI)",
        [139] = "NetBIOS session service (legacy file sharing)",
        [143] = "IMAP mail",
        [389] = "LDAP (Active Directory)",
        [443] = "HTTPS / TLS (web; MeshCentral server default agent + web port)",
        [445] = "SMB file sharing",
        [465] = "SMTP over TLS",
        [587] = "SMTP submission",
        [623] = "Intel AMT / IPMI (RMCP)",
        [636] = "LDAP over TLS",
        [664] = "Intel AMT / ASF secure RMCP",
        [993] = "IMAP over TLS",
        [995] = "POP3 over TLS",
        [1433] = "Microsoft SQL Server",
        [1688] = "KMS Windows activation",
        [2869] = "UPnP / SSDP event notification (Windows)",
        [3268] = "Active Directory Global Catalog",
        [3269] = "Active Directory Global Catalog over TLS",
        [3306] = "MySQL / MariaDB",
        [3389] = "Remote Desktop Protocol (RDP)",
        [4433] = "MeshCentral MPS (Intel AMT CIRA) default port",
        [5040] = "Windows Connected Devices Platform (CDPSvc)",
        [5222] = "XMPP / push messaging",
        [5357] = "Web Services on Devices (WSDAPI)",
        [5432] = "PostgreSQL",
        [5800] = "VNC over HTTP",
        [5900] = "VNC remote desktop",
        [5938] = "TeamViewer",
        [5985] = "WinRM (PowerShell remoting, HTTP)",
        [5986] = "WinRM (PowerShell remoting, HTTPS)",
        [6568] = "AnyDesk",
        [7070] = "AnyDesk (direct connections)",
        [7680] = "Windows Update Delivery Optimization (peer-to-peer)",
        [8040] = "ScreenConnect / ConnectWise Control relay (common)",
        [8041] = "ScreenConnect / ConnectWise Control relay",
        [8080] = "HTTP alternate / proxy",
        [8443] = "HTTPS alternate (often used for MeshCentral or other web consoles)",
        [9100] = "Printer (raw / JetDirect)",
        [16992] = "Intel AMT (HTTP)",
        [16993] = "Intel AMT (HTTPS)",
        [16994] = "Intel AMT redirection (SOL/IDER)",
        [16995] = "Intel AMT redirection over TLS",
        [21115] = "RustDesk",
        [21116] = "RustDesk",
        [21117] = "RustDesk relay",
    };

    private static readonly Dictionary<int, string> Udp = new()
    {
        [53] = "DNS",
        [67] = "DHCP server",
        [68] = "DHCP client",
        [123] = "NTP time synchronisation",
        [137] = "NetBIOS name service",
        [138] = "NetBIOS datagram service",
        [161] = "SNMP",
        [443] = "QUIC / HTTP3",
        [500] = "IPsec IKE (VPN)",
        [1900] = "SSDP / UPnP discovery",
        [3478] = "STUN / TURN (Teams, WebRTC)",
        [3702] = "WS-Discovery",
        [4500] = "IPsec NAT-T (VPN)",
        [5050] = "Multimedia conferencing",
        [5353] = "mDNS (multicast DNS)",
        [5355] = "LLMNR (link-local name resolution)",
        [16990] = "MeshAgent LAN-mode / Intel AMT local discovery (multicast)",
        [16989] = "MeshCentral server LAN discovery (multicast)",
    };

    /// <summary>Process names (lower-case, without .exe) with a known networking role.</summary>
    private static readonly Dictionary<string, string> ProcessRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["svchost"] = "Windows service host",
        ["lsass"] = "Windows authentication (LSA)",
        ["system"] = "Windows kernel (SMB/HTTP.sys/NetBIOS)",
        ["spoolsv"] = "Print spooler",
        ["services"] = "Service Control Manager",
        ["wininit"] = "Windows init (RPC)",
        ["msmpeng"] = "Microsoft Defender antivirus",
        ["mssense"] = "Microsoft Defender for Endpoint sensor",
        ["teamviewer"] = "TeamViewer remote access",
        ["teamviewer_service"] = "TeamViewer remote access service",
        ["anydesk"] = "AnyDesk remote access",
        ["rustdesk"] = "RustDesk remote access",
        ["screenconnect.clientservice"] = "ScreenConnect remote access",
        ["remoting_host"] = "Chrome Remote Desktop host",
        ["tvnserver"] = "TightVNC server",
        ["winvnc"] = "VNC server",
        ["chrome"] = "Google Chrome browser",
        ["msedge"] = "Microsoft Edge browser",
        ["firefox"] = "Mozilla Firefox browser",
        ["ms-teams"] = "Microsoft Teams",
        ["teams"] = "Microsoft Teams (classic)",
        ["zoom"] = "Zoom",
        ["outlook"] = "Microsoft Outlook",
        ["onedrive"] = "Microsoft OneDrive sync",
    };

    public static string? DescribeTcpPort(int port) => Tcp.TryGetValue(port, out var s) ? s : null;
    public static string? DescribeUdpPort(int port) => Udp.TryGetValue(port, out var s) ? s : null;

    public static string? DescribePort(string protocol, int port) =>
        protocol.StartsWith("UDP", StringComparison.OrdinalIgnoreCase) ? DescribeUdpPort(port) : DescribeTcpPort(port);

    public static bool IsEphemeral(int port) => port >= 49152;

    /// <summary>Builds a one-line purpose description for a connection.</summary>
    public static string Describe(string protocol, int localPort, int remotePort, string state, string processName, bool isMeshAgent)
    {
        var name = StripExe(processName).ToLowerInvariant();
        var isUdp = protocol.StartsWith("UDP", StringComparison.OrdinalIgnoreCase);
        var listening = isUdp || state is "LISTEN" or "LISTENING";

        if (isMeshAgent)
        {
            if (listening)
                return $"MeshCentral agent local endpoint ({DescribePort(protocol, localPort) ?? "agent-internal / discovery"})";
            return $"MeshCentral agent -> server control/relay channel (WebSocket over TLS, remote port {remotePort}" +
                   (DescribeTcpPort(remotePort) is { } rp ? $": {rp}" : "") + ")";
        }

        string? portText;
        if (listening)
        {
            portText = DescribePort(protocol, localPort);
            if (portText == null && localPort is >= 49664 and <= 49699 && name is "lsass" or "wininit" or "services" or "spoolsv" or "svchost")
                portText = "Dynamic RPC endpoint";
            var role = ProcessRoles.TryGetValue(name, out var r) ? r : null;
            return "Listening: " + (portText ?? (IsEphemeral(localPort) ? "dynamic/ephemeral port" : "unregistered port")) +
                   (role != null ? $" ({role})" : "");
        }

        portText = DescribeTcpPort(remotePort) ?? DescribeTcpPort(localPort);
        var procRole = ProcessRoles.TryGetValue(name, out var pr) ? pr : null;
        if (portText != null && procRole != null) return $"{procRole}: {portText}";
        if (portText != null) return portText;
        if (procRole != null) return procRole;
        return IsEphemeral(remotePort) ? "Application traffic (dynamic port)" : $"Application traffic (port {remotePort})";
    }

    public static string StripExe(string name) =>
        name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
}
