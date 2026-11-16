using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal sealed class BrowserProxy : IDisposable
{
    private readonly TcpListener listener;
    private readonly Func<string, int, CancellationToken, Task<TcpClient>> connect;
    private readonly HashSet<TcpClient> clients = new HashSet<TcpClient>();
    private readonly CancellationTokenSource stopped = new CancellationTokenSource();
    private readonly CancellationToken stopToken;
    private int disposed;
    internal int Port { get; private set; }

    internal BrowserProxy(int port, Func<string, int, CancellationToken, Task<TcpClient>> connect)
    {
        this.connect = connect;
        stopToken = stopped.Token;
        listener = new TcpListener(IPAddress.Loopback, port) { ExclusiveAddressUse = true };
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        AcceptClients();
    }

    internal static string PacUrl(int port)
    {
        string vpnOnly = string.Join("|", BrowserLan.VpnOnlyZones.Select(zone => zone.Replace(".", "\\.")));
        string script = "function FindProxyForURL(url,host){" +
            "host=host.toLowerCase().replace(/\\.+$/,'');" +
            "return (/\\.(ru|xn--p1ai|\\u0440\\u0444)$/.test(host) || /(^|\\.)(" + vpnOnly + ")$/.test(host))" +
            " ? 'SOCKS5 127.0.0.1:" + port + "' : 'DIRECT';}";
        return "data:application/x-ns-proxy-autoconfig;base64," + Convert.ToBase64String(Encoding.ASCII.GetBytes(script));
    }

    internal static void OpenBrowser(string dataRoot, bool edge)
    {
        string name = edge ? "Edge" : "Chrome";
        string relative = edge ? @"Microsoft\Edge\Application\msedge.exe" : @"Google\Chrome\Application\chrome.exe";
        string executable = null;
        foreach (Environment.SpecialFolder folder in new[] { Environment.SpecialFolder.ProgramFiles,
            Environment.SpecialFolder.ProgramFilesX86, Environment.SpecialFolder.LocalApplicationData }) {
            string root = Environment.GetFolderPath(folder);
            if (string.IsNullOrEmpty(root)) continue;
            string path = Path.Combine(root, relative);
            if (File.Exists(path)) { executable = path; break; }
        }
        if (executable == null) throw new FileNotFoundException("Не найден " + name + ". Выберите другой браузер из меню.");

        var lan = new BrowserLan();
        int[] interfaces = lan.Interfaces();
        if (interfaces[0] == 0 && interfaces[1] == 0)
            throw new IOException("У физического адаптера нет маршрута в интернет. Проверьте Wi-Fi или Ethernet.");

        string profile = Path.Combine(dataRoot, "browser-proxy", name);
        using (var proxy = new BrowserProxy(27655, lan.Connect)) {
            var start = new ProcessStartInfo(executable,
                "--user-data-dir=\"" + profile + "\" --proxy-pac-url=" + PacUrl(proxy.Port) +
                " --no-first-run --new-window about:blank") { UseShellExecute = false };
            using (Process browser = Process.Start(start)) { }
            Console.WriteLine("Прокси запущен на 127.0.0.1:" + proxy.Port + ". " +
                "Прямой интерфейс: IPv4 " + (interfaces[0] == 0 ? "недоступен" : "найден") +
                ", IPv6 " + (interfaces[1] == 0 ? "недоступен" : "найден") + ".");
            Console.WriteLine("Сайты .ru и .рф открывайте в запущенном окне " + name + ".");
            Console.WriteLine("Для ChatGPT используйте обычное окно браузера с защитой VPN.");
            Console.WriteLine("Для остановки закройте это окно браузера и нажмите Enter здесь.");
            Console.ReadLine();
        }
    }

    private async void AcceptClients()
    {
        try {
            while (!stopToken.IsCancellationRequested) {
                TcpClient client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
                lock (clients) {
                    if (stopToken.IsCancellationRequested || clients.Count >= 96) { client.Close(); continue; }
                    clients.Add(client);
                }
                Serve(client);
            }
        } catch (SocketException error) {
            if (!stopToken.IsCancellationRequested) Console.Error.WriteLine(error.Message);
        } catch (ObjectDisposedException) { }
    }

    private async void Serve(TcpClient client)
    {
        try {
            using (NetworkStream incoming = client.GetStream()) {
                TcpClient upstream;
                using (var handshake = CancellationTokenSource.CreateLinkedTokenSource(stopToken)) {
                    handshake.CancelAfter(15000);
                    using (handshake.Token.Register(client.Close))
                        upstream = await OpenTunnel(incoming, handshake.Token).ConfigureAwait(false);
                }
                if (upstream == null) return;
                using (upstream)
                using (stopToken.Register(upstream.Close)) {
                    NetworkStream outgoing = upstream.GetStream();
                    await Task.WhenAll(Copy(incoming, outgoing, upstream.Client), Copy(outgoing, incoming, client.Client))
                        .ConfigureAwait(false);
                }
            }
        } catch (Exception error) {
            // Protocol, DNS and socket failures are isolated to this connection.
            Trace.WriteLine(error.GetType().Name + ": " + error.Message);
        } finally {
            client.Close();
            lock (clients) clients.Remove(client);
        }
    }

    private async Task<TcpClient> OpenTunnel(NetworkStream stream, CancellationToken token)
    {
        byte[] greeting = await ReadBytes(stream, 2, token).ConfigureAwait(false);
        if (greeting[0] != 5 || greeting[1] == 0) return null;
        byte[] methods = await ReadBytes(stream, greeting[1], token).ConfigureAwait(false);
        bool noAuth = Array.IndexOf(methods, (byte)0) >= 0;
        await stream.WriteAsync(new byte[] { 5, noAuth ? (byte)0 : (byte)255 }, 0, 2, token).ConfigureAwait(false);
        if (!noAuth) return null;

        byte[] request = await ReadBytes(stream, 4, token).ConfigureAwait(false);
        if (request[0] != 5 || request[2] != 0) return null;
        int length;
        switch (request[3]) {
            case 1: length = 4; break;
            case 3: length = (await ReadBytes(stream, 1, token).ConfigureAwait(false))[0]; break;
            case 4: length = 16; break;
            default: await Reply(stream, 8, token).ConfigureAwait(false); return null;
        }
        byte[] authority = await ReadBytes(stream, length + 2, token).ConfigureAwait(false);
        if (request[1] != 1 || request[3] != 3) {
            await Reply(stream, request[1] != 1 ? (byte)7 : (byte)8, token).ConfigureAwait(false);
            return null;
        }
        string host = BrowserLan.HostName(new UTF8Encoding(false, true).GetString(authority, 0, length));
        int port = authority[length] * 256 + authority[length + 1];
        if (port == 0 || !IsBypassedHost(host)) {
            await Reply(stream, 2, token).ConfigureAwait(false);
            return null;
        }

        TcpClient upstream;
        try { upstream = await connect(host, port, token).ConfigureAwait(false); }
        catch (Exception error) {
            Trace.WriteLine(error.GetType().Name + ": " + error.Message);
            upstream = null;
        }
        try {
            await Reply(stream, upstream == null ? (byte)4 : (byte)0, token).ConfigureAwait(false);
            return upstream;
        } catch {
            if (upstream != null) upstream.Close();
            throw;
        }
    }

    private static bool IsBypassedHost(string host)
    {
        return host.EndsWith(".ru", StringComparison.Ordinal) || host.EndsWith(".xn--p1ai", StringComparison.Ordinal);
    }

    private static Task Reply(Stream stream, byte code, CancellationToken token)
    {
        byte[] message = { 5, code, 0, 1, 0, 0, 0, 0, 0, 0 };
        return stream.WriteAsync(message, 0, message.Length, token);
    }

    private static async Task<byte[]> ReadBytes(Stream stream, int count, CancellationToken token)
    {
        byte[] bytes = new byte[count];
        for (int offset = 0; offset < count;) {
            int read = await stream.ReadAsync(bytes, offset, count - offset, token).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException();
            offset += read;
        }
        return bytes;
    }

    private static async Task Copy(Stream source, Stream target, Socket socket)
    {
        try { await source.CopyToAsync(target).ConfigureAwait(false); }
        finally {
            try { socket.Shutdown(SocketShutdown.Send); }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) != 0) return;
        stopped.Cancel();
        listener.Stop();
        lock (clients) foreach (TcpClient client in clients.ToArray()) client.Close();
        stopped.Dispose();
    }
}
