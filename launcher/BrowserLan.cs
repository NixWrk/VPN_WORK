using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

internal sealed class BrowserLan
{
    private const ushort A = 1, Cname = 5, Aaaa = 28;
    internal static readonly string[] VpnOnlyZones = {
        "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "oaistatsig.com", "openaimerge.com"
    };
    private readonly object routeLock = new object();
    private int ipv4, ipv6;
    private DateTime refreshAt;

    internal static string HostName(string name)
    {
        try { return new IdnMapping { UseStd3AsciiRules = true }.GetAscii(name.TrimEnd('.')).ToLowerInvariant(); }
        catch (ArgumentException) { return ""; }
    }

    internal static bool IsVpnOnly(string name)
    {
        return VpnOnlyZones.Any(zone => name == zone || name.EndsWith("." + zone, StringComparison.Ordinal));
    }

    internal static bool IsPublicAddress(IPAddress address)
    {
        byte[] bytes = address.GetAddressBytes();
        if (bytes.Length == 16) {
            if ((bytes[0] & 0xe0) == 0x20) return true;
            // RFC 6052 well-known NAT64 prefix. Check the embedded IPv4 as well.
            return bytes[0] == 0 && bytes[1] == 0x64 && bytes[2] == 0xff && bytes[3] == 0x9b &&
                bytes.Skip(4).Take(8).All(b => b == 0) && IsPublicAddress(new IPAddress(bytes.Skip(12).ToArray()));
        }
        int first = bytes[0], second = bytes[1];
        return first > 0 && first < 224 && first != 10 && first != 127 &&
            !(first == 100 && second >= 64 && second <= 127) &&
            !(first == 169 && second == 254) && !(first == 172 && second >= 16 && second <= 31) &&
            !(first == 192 && second == 168) && !(first == 198 && (second == 18 || second == 19));
    }

    private void RefreshRoutes()
    {
        var hardware = new HashSet<int>();
        using (var adapters = new ManagementObjectSearcher(@"root\StandardCimv2",
            "SELECT InterfaceIndex FROM MSFT_NetAdapter WHERE HardwareInterface = TRUE"))
        using (var rows = adapters.Get())
            foreach (ManagementObject row in rows)
                using (row) hardware.Add(Convert.ToInt32(row["InterfaceIndex"]));

        var eligibleV4 = new HashSet<int>();
        var eligibleV6 = new HashSet<int>();
        foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces()) {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            IPInterfaceProperties ip = nic.GetIPProperties();
            if (nic.Supports(NetworkInterfaceComponent.IPv4)) eligibleV4.Add(ip.GetIPv4Properties().Index);
            if (nic.Supports(NetworkInterfaceComponent.IPv6) && ip.UnicastAddresses.Any(a =>
                a.Address.AddressFamily == AddressFamily.InterNetworkV6 && IsPublicAddress(a.Address)))
                eligibleV6.Add(ip.GetIPv6Properties().Index);
        }

        int bestV4 = 0, bestV6 = 0;
        long metricV4 = long.MaxValue, metricV6 = long.MaxValue;
        using (var routes = new ManagementObjectSearcher(@"root\StandardCimv2",
            "SELECT InterfaceIndex, InterfaceMetric, RouteMetric, DestinationPrefix, NextHop FROM MSFT_NetRoute " +
            "WHERE DestinationPrefix = '0.0.0.0/0' OR DestinationPrefix = '::/0'"))
        using (var rows = routes.Get())
            foreach (ManagementObject row in rows) {
                using (row) {
                    int index = Convert.ToInt32(row["InterfaceIndex"]);
                    if (!hardware.Contains(index)) continue;
                    var hop = IPAddress.Parse((string)row["NextHop"]);
                    if (hop.Equals(IPAddress.Any) || hop.Equals(IPAddress.IPv6Any)) continue;
                    long metric = Convert.ToInt64(row["InterfaceMetric"]) + Convert.ToInt64(row["RouteMetric"]);
                    if ((string)row["DestinationPrefix"] == "::/0") {
                        if (metric < metricV6 && eligibleV6.Contains(index)) { bestV6 = index; metricV6 = metric; }
                    } else if (metric < metricV4 && eligibleV4.Contains(index)) {
                        bestV4 = index; metricV4 = metric;
                    }
                }
            }
        ipv4 = bestV4;
        ipv6 = bestV6;
        refreshAt = DateTime.UtcNow.AddSeconds(5);
    }

    internal int[] Interfaces()
    {
        lock (routeLock) {
            if (DateTime.UtcNow >= refreshAt) RefreshRoutes();
            return new[] { ipv4, ipv6 };
        }
    }

    internal Task<TcpClient> Connect(string host, int port, CancellationToken token)
    {
        int[] interfaces = Interfaces();
        return ConnectFamilies(
            interfaces[1] == 0 ? (Func<CancellationToken, Task<TcpClient>>)null :
                cancellation => ConnectOnPath(host, port, interfaces[1], Aaaa, cancellation),
            interfaces[0] == 0 ? (Func<CancellationToken, Task<TcpClient>>)null :
                cancellation => ConnectOnPath(host, port, interfaces[0], A, cancellation), token);
    }

    internal static async Task<TcpClient> ConnectFamilies(Func<CancellationToken, Task<TcpClient>> v6,
        Func<CancellationToken, Task<TcpClient>> v4, CancellationToken token)
    {
        if (v6 == null) return v4 == null ? null : await v4(token).ConfigureAwait(false);
        if (v4 == null) return await v6(token).ConfigureAwait(false);

        using (var race = CancellationTokenSource.CreateLinkedTokenSource(token)) {
            Task<TcpClient> preferred = v6(race.Token);
            if (await Task.WhenAny(preferred, Task.Delay(250, token)).ConfigureAwait(false) == preferred) {
                TcpClient result = await preferred.ConfigureAwait(false);
                return result ?? await v4(token).ConfigureAwait(false);
            }
            Task<TcpClient> fallback = v4(race.Token);
            Task<TcpClient> first = await Task.WhenAny(preferred, fallback).ConfigureAwait(false);
            Task<TcpClient> remaining = first == preferred ? fallback : preferred;
            bool useRemaining = false;
            try {
                TcpClient connection = await first.ConfigureAwait(false);
                if (connection != null) return connection;
                useRemaining = true;
                return await remaining.ConfigureAwait(false);
            } finally {
                if (!useRemaining) {
                    race.Cancel();
                    CloseUnusedConnection(remaining);
                }
            }
        }
    }

    private static void CloseUnusedConnection(Task<TcpClient> connection)
    {
        connection.ContinueWith(task => {
            if (task.Status == TaskStatus.RanToCompletion && task.Result != null) task.Result.Close();
            if (task.IsFaulted) task.Exception.Handle(error => true);
        }, TaskScheduler.Default);
    }

    private static async Task<TcpClient> ConnectOnPath(string host, int port, int index, ushort type, CancellationToken token)
    {
        IPAddress[] addresses = await ResolveWithFallback(() => Resolve(host, index, type),
            () => Resolve(host, 0, type), token).ConfigureAwait(false);
        foreach (IPAddress address in addresses) {
            if (token.IsCancellationRequested) break;
            TcpClient connection = await Dial(address, port, index, token).ConfigureAwait(false);
            if (connection != null) return connection;
        }
        return null;
    }

    internal static async Task<IPAddress[]> ResolveWithFallback(Func<IPAddress[]> local,
        Func<IPAddress[]> windows, CancellationToken token)
    {
        Task<IPAddress[]> preferred = Task.Run(local, token);
        if (await Task.WhenAny(preferred, Task.Delay(350, token)).ConfigureAwait(false) == preferred) {
            IPAddress[] addresses = await preferred.ConfigureAwait(false);
            return addresses.Length > 0 ? addresses : await Task.Run(windows, token).ConfigureAwait(false);
        }

        // A VPN can silently drop queries on the LAN. Give the system resolver
        // a chance to answer while Windows is still waiting for that LAN query.
        Task<IPAddress[]> fallback = Task.Run(windows, token);
        Task<IPAddress[]> first = await Task.WhenAny(preferred, fallback).ConfigureAwait(false);
        Task<IPAddress[]> remaining = first == preferred ? fallback : preferred;
        try {
            IPAddress[] addresses = await first.ConfigureAwait(false);
            return addresses.Length > 0 ? addresses : await remaining.ConfigureAwait(false);
        } finally {
            ObserveUnusedDns(remaining);
        }
    }

    private static void ObserveUnusedDns(Task unused)
    {
        unused.ContinueWith(task => task.Exception.Handle(error => true),
            CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
    }

    internal static async Task<TcpClient> Dial(IPAddress address, int port, int index, CancellationToken token)
    {
        var client = new TcpClient(address.AddressFamily);
        bool connected = false;
        try {
            // Windows expects IP_UNICAST_IF in network byte order and IPV6_UNICAST_IF in host byte order.
            bool ipv6 = address.AddressFamily == AddressFamily.InterNetworkV6;
            client.Client.SetSocketOption(ipv6 ? SocketOptionLevel.IPv6 : SocketOptionLevel.IP,
                (SocketOptionName)31, ipv6 ? index : IPAddress.HostToNetworkOrder(index));
            using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(token)) {
                timeout.CancelAfter(3500);
                using (timeout.Token.Register(client.Close))
                    await client.ConnectAsync(address, port).ConfigureAwait(false);
                if (timeout.IsCancellationRequested) return null;
            }
            connected = true;
            return client;
        } catch (SocketException) { return null; }
          catch (ObjectDisposedException) { return null; }
        finally { if (!connected) client.Close(); }
    }

    private static IPAddress[] Resolve(string host, int index, ushort type)
    {
        const ulong dnsOnly = 0x40 | 0x80 | 0x800 | 0x1000; // No hosts, NetBT or multicast. Treat as FQDN.
        var request = new DnsRequest { Version = 1, Name = host, Type = type, Options = dnsOnly, InterfaceIndex = (uint)index };
        var result = new DnsResult { Version = 1 };
        var addresses = new List<IPAddress>();
        try {
            if (DnsQueryEx(ref request, ref result, IntPtr.Zero) != 0 || result.Status != 0) return addresses.ToArray();
            for (IntPtr pointer = result.Records; pointer != IntPtr.Zero;) {
                var record = (DnsRecord)Marshal.PtrToStructure(pointer, typeof(DnsRecord));
                IntPtr data = IntPtr.Add(pointer, DnsRecordDataOffset);
                pointer = record.Next;
                if (IsVpnOnly(HostName(Marshal.PtrToStringUni(record.Name) ?? "")) ||
                    (record.Type == Cname && IsVpnOnly(HostName(Marshal.PtrToStringUni(Marshal.ReadIntPtr(data)) ?? ""))))
                    throw new IOException("VPN-only DNS alias.");
                int length = type == A ? 4 : 16;
                if (record.Type != type || record.Length != length || (record.Flags & 3) != 1) continue;
                byte[] bytes = new byte[length];
                Marshal.Copy(data, bytes, 0, length);
                var address = new IPAddress(bytes);
                if (IsPublicAddress(address)) addresses.Add(address);
            }
            return addresses.Distinct().ToArray();
        } finally {
            if (result.Records != IntPtr.Zero) DnsRecordListFree(result.Records, 1); // DnsFreeRecordList
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DnsRequest
    {
        public uint Version;
        [MarshalAs(UnmanagedType.LPWStr)] public string Name;
        public ushort Type;
        public ulong Options;
        public IntPtr ServerList;
        public uint InterfaceIndex;
        public IntPtr Callback, Context;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsResult
    {
        public uint Version;
        public int Status;
        public ulong Options;
        public IntPtr Records, Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsRecord
    {
        public IntPtr Next, Name;
        public ushort Type, Length;
        public uint Flags, Ttl, Reserved;
        public IntPtr Data;
    }

    private static readonly int DnsRecordDataOffset = Marshal.OffsetOf(typeof(DnsRecord), "Data").ToInt32();

    [DllImport("dnsapi.dll", ExactSpelling = true)]
    private static extern int DnsQueryEx(ref DnsRequest request, ref DnsResult result, IntPtr cancel);
    [DllImport("dnsapi.dll", ExactSpelling = true)]
    private static extern void DnsRecordListFree(IntPtr records, int freeType);
}
