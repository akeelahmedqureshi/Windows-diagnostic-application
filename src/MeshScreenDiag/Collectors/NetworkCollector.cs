using System.Net;
using System.Runtime.InteropServices;
using MeshScreenDiag.Core.Catalogs;
using MeshScreenDiag.Core.Models;
using static MeshScreenDiag.Native.NativeMethods;

namespace MeshScreenDiag.Collectors;

/// <summary>
/// All TCP/UDP endpoints (IPv4 + IPv6) with their owning process, read from the IP Helper API
/// (the same data as "netstat -ano"). Does not open, probe or modify any connection.
/// </summary>
internal static class NetworkCollector
{
    private static readonly string[] TcpStates =
    {
        "UNKNOWN", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT1",
        "FIN_WAIT2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB",
    };

    public static List<NetConnection> Collect(IReadOnlyDictionary<int, ProcessInfo> processes, ISet<int> meshPids, List<string> errors)
    {
        var list = new List<NetConnection>(512);
        try { ReadTcp4(list); } catch (Exception ex) { errors.Add("TCP/IPv4 table: " + ex.Message); }
        try { ReadTcp6(list); } catch (Exception ex) { errors.Add("TCP/IPv6 table: " + ex.Message); }
        try { ReadUdp4(list); } catch (Exception ex) { errors.Add("UDP/IPv4 table: " + ex.Message); }
        try { ReadUdp6(list); } catch (Exception ex) { errors.Add("UDP/IPv6 table: " + ex.Message); }

        foreach (var c in list)
        {
            if (processes.TryGetValue(c.Pid, out var p))
            {
                c.ProcessName = p.Name;
                c.ProcessPath = p.Path;
            }
            else
            {
                c.ProcessName = c.Pid switch { 0 => "System Idle", 4 => "System", _ => $"PID {c.Pid}" };
            }
            c.IsMeshAgent = meshPids.Contains(c.Pid);
            c.Purpose = PortCatalog.Describe(c.Protocol, c.LocalPort, c.RemotePort, c.State, c.ProcessName, c.IsMeshAgent);
        }
        return list;
    }

    private static IntPtr GetTable(bool tcp, int af, out int rows)
    {
        var size = 0;
        uint ret = tcp
            ? GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
            : GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, UDP_TABLE_OWNER_PID, 0);
        for (var attempt = 0; attempt < 5; attempt++)
        {
            size += 4096; // the table can grow between the two calls
            var buf = Marshal.AllocHGlobal(size);
            ret = tcp
                ? GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
                : GetExtendedUdpTable(buf, ref size, false, af, UDP_TABLE_OWNER_PID, 0);
            if (ret == 0)
            {
                rows = Marshal.ReadInt32(buf);
                return buf;
            }
            Marshal.FreeHGlobal(buf);
            if (ret != ERROR_INSUFFICIENT_BUFFER) break;
        }
        throw new InvalidOperationException($"IP helper returned error {ret}");
    }

    private static int Port(int raw) => ((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF);

    private static string V4(int raw) => new IPAddress((uint)raw).ToString();

    private static string V6(IntPtr p)
    {
        var bytes = new byte[16];
        Marshal.Copy(p, bytes, 0, 16);
        return new IPAddress(bytes).ToString();
    }

    private static string State(int s) => s >= 0 && s < TcpStates.Length ? TcpStates[s] : s.ToString();

    // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid (6 DWORDs)
    private static void ReadTcp4(List<NetConnection> list)
    {
        var buf = GetTable(true, AF_INET, out var rows);
        try
        {
            for (var i = 0; i < rows; i++)
            {
                var row = buf + 4 + i * 24;
                list.Add(new NetConnection
                {
                    Protocol = "TCP",
                    IpVersion = 4,
                    State = State(Marshal.ReadInt32(row, 0)),
                    LocalAddress = V4(Marshal.ReadInt32(row, 4)),
                    LocalPort = Port(Marshal.ReadInt32(row, 8)),
                    RemoteAddress = V4(Marshal.ReadInt32(row, 12)),
                    RemotePort = Port(Marshal.ReadInt32(row, 16)),
                    Pid = Marshal.ReadInt32(row, 20),
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid (56 bytes)
    private static void ReadTcp6(List<NetConnection> list)
    {
        var buf = GetTable(true, AF_INET6, out var rows);
        try
        {
            for (var i = 0; i < rows; i++)
            {
                var row = buf + 4 + i * 56;
                list.Add(new NetConnection
                {
                    Protocol = "TCP",
                    IpVersion = 6,
                    LocalAddress = V6(row),
                    LocalPort = Port(Marshal.ReadInt32(row, 20)),
                    RemoteAddress = V6(row + 24),
                    RemotePort = Port(Marshal.ReadInt32(row, 44)),
                    State = State(Marshal.ReadInt32(row, 48)),
                    Pid = Marshal.ReadInt32(row, 52),
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid (12 bytes)
    private static void ReadUdp4(List<NetConnection> list)
    {
        var buf = GetTable(false, AF_INET, out var rows);
        try
        {
            for (var i = 0; i < rows; i++)
            {
                var row = buf + 4 + i * 12;
                list.Add(new NetConnection
                {
                    Protocol = "UDP",
                    IpVersion = 4,
                    State = "",
                    LocalAddress = V4(Marshal.ReadInt32(row, 0)),
                    LocalPort = Port(Marshal.ReadInt32(row, 4)),
                    Pid = Marshal.ReadInt32(row, 8),
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, pid (28 bytes)
    private static void ReadUdp6(List<NetConnection> list)
    {
        var buf = GetTable(false, AF_INET6, out var rows);
        try
        {
            for (var i = 0; i < rows; i++)
            {
                var row = buf + 4 + i * 28;
                list.Add(new NetConnection
                {
                    Protocol = "UDP",
                    IpVersion = 6,
                    State = "",
                    LocalAddress = V6(row),
                    LocalPort = Port(Marshal.ReadInt32(row, 20)),
                    Pid = Marshal.ReadInt32(row, 24),
                });
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
    }
}
