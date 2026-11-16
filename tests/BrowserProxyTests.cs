using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal static class BrowserProxyTests
{
    private static int calls;
    private static string lastHost;

    private static void Main()
    {
        var loopback = NetworkInterface.GetAllNetworkInterfaces().First(n => n.NetworkInterfaceType == NetworkInterfaceType.Loopback);
        var loopbackProperties = loopback.GetIPProperties();
        int v4Index = loopbackProperties.GetIPv4Properties().Index;
        int v6Index = loopbackProperties.GetIPv6Properties().Index;
        var server4 = new TcpListener(IPAddress.Loopback, 0);
        var server6 = new TcpListener(IPAddress.IPv6Loopback, 0);
        server4.Start();
        server6.Start();
        try {
            using (var proxy = new BrowserProxy(0, (host, port, token) => {
                lastHost = host;
                Interlocked.Increment(ref calls);
                if (host == "missing.ru") return Task.FromResult<TcpClient>(null);
                Func<CancellationToken, Task<TcpClient>> v4 = t =>
                    BrowserLan.Dial(IPAddress.Loopback, ((IPEndPoint)server4.LocalEndpoint).Port, v4Index, t);
                Func<CancellationToken, Task<TcpClient>> v6 = t =>
                    BrowserLan.Dial(IPAddress.IPv6Loopback, ((IPEndPoint)server6.LocalEndpoint).Port, v6Index, t);
                if (host == "ipv4.ru") v6 = null;
                if (host == "fallback.ru") v6 = async t => { await Task.Delay(2000, t); return null; };
                return BrowserLan.ConnectFamilies(v6, v4, token);
            })) {
                Transfer(proxy.Port, "ipv4.RU.", server4, "ipv4.ru");
                Transfer(proxy.Port, "пример.рф.", server6, "xn--e1afmkfd.xn--p1ai");
                Transfer(proxy.Port, "fallback.ru", server4, "fallback.ru");
                int before = calls;
                Denied(proxy.Port, DomainRequest("ru.example.net"), 2);
                Denied(proxy.Port, DomainRequest("chatgpt.com"), 2);
                Denied(proxy.Port, DomainRequest("xn--e1afmkfd.xn--p1ai.example"), 2);
                Denied(proxy.Port, new byte[] { 5, 1, 0, 1, 127, 0, 0, 1, 0, 80 }, 8);
                byte[] udp = DomainRequest("site.ru"); udp[1] = 3;
                Denied(proxy.Port, udp, 7);
                if (calls != before) throw new Exception("A disallowed request reached the connector.");
                Denied(proxy.Port, DomainRequest("missing.ru"), 4);
                string pac = Encoding.ASCII.GetString(Convert.FromBase64String(BrowserProxy.PacUrl(proxy.Port).Split(',')[1]));
                if (!pac.Contains("xn--p1ai") || !pac.Contains("chatgpt\\.com") ||
                    !pac.Contains("'SOCKS5 127.0.0.1:" + proxy.Port + "' : 'DIRECT'"))
                    throw new Exception("Browser PAC does not isolate the managed zones.");
            }
            foreach (string address in new[] { "198.18.0.1", "198.19.0.1", "127.0.0.1", "192.168.0.1", "::1", "fc00::1", "fe80::1", "::ffff:1.1.1.1" })
                if (BrowserLan.IsPublicAddress(IPAddress.Parse(address))) throw new Exception("Unsafe DNS address accepted: " + address);
            foreach (string address in new[] { "1.1.1.1", "2606:4700:4700::1111", "64:ff9b::101:101" })
                if (!BrowserLan.IsPublicAddress(IPAddress.Parse(address))) throw new Exception("Usable address rejected: " + address);
            if (!BrowserLan.IsVpnOnly(BrowserLan.HostName("CDN.OAIUSERCONTENT.COM."))) throw new Exception("VPN-only DNS alias accepted.");
            var blockedLanDns = new TaskCompletionSource<bool>();
            try {
                IPAddress answer = IPAddress.Parse("1.1.1.1");
                Task<IPAddress[]> resolved = BrowserLan.ResolveWithFallback(() => {
                    blockedLanDns.Task.GetAwaiter().GetResult();
                    return new IPAddress[0];
                }, () => new[] { answer }, CancellationToken.None);
                if (!resolved.Wait(3000) || !resolved.Result.SequenceEqual(new[] { answer }))
                    throw new Exception("An unanswered LAN DNS query delayed the first connection.");
            } finally { blockedLanDns.SetResult(true); }
        } finally {
            server4.Stop();
            server6.Stop();
        }
        Console.WriteLine("PASS: SOCKS5 first request, IPv4/IPv6 interface binding, IPv4 fallback, IDN, blocked destinations and relay");
    }

    private static void Transfer(int port, string host, TcpListener listener, string normalized)
    {
        Task<TcpClient> accept = listener.AcceptTcpClientAsync();
        using (TcpClient browser = Begin(port, DomainRequest(host))) {
            NetworkStream client = browser.GetStream();
            if (Read(client, 10)[1] != 0 || lastHost != normalized || !accept.Wait(4000))
                throw new Exception("First connection failed or used the wrong address family for " + host);
            using (TcpClient server = accept.Result) {
                server.ReceiveTimeout = 4000;
                NetworkStream upstream = server.GetStream();
                client.WriteByte(42);
                if (upstream.ReadByte() != 42) throw new Exception("Client traffic did not reach the endpoint.");
                upstream.WriteByte(99);
                if (client.ReadByte() != 99) throw new Exception("Endpoint response did not reach the client.");
            }
        }
    }

    private static void Denied(int port, byte[] request, byte code)
    {
        using (TcpClient client = Begin(port, request))
            if (Read(client.GetStream(), 10)[1] != code) throw new Exception("Incorrect SOCKS5 failure code.");
    }

    private static TcpClient Begin(int port, byte[] request)
    {
        var client = new TcpClient("127.0.0.1", port) { ReceiveTimeout = 5000 };
        NetworkStream stream = client.GetStream();
        stream.WriteByte(5);
        stream.Write(new byte[] { 1, 0 }, 0, 2);
        if (!Read(stream, 2).SequenceEqual(new byte[] { 5, 0 })) throw new Exception("SOCKS5 negotiation failed.");
        stream.Write(request, 0, request.Length);
        return client;
    }

    private static byte[] DomainRequest(string host)
    {
        byte[] name = Encoding.UTF8.GetBytes(host);
        return new byte[] { 5, 1, 0, 3, (byte)name.Length }.Concat(name).Concat(new byte[] { 0, 80 }).ToArray();
    }

    private static byte[] Read(Stream stream, int count)
    {
        using (var bytes = new BinaryReader(stream, Encoding.ASCII, true)) {
            byte[] value = bytes.ReadBytes(count);
            if (value.Length != count) throw new EndOfStreamException();
            return value;
        }
    }
}
