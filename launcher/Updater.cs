using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

internal static class Updater
{
    private const string Repository = "NixWrk/VPN_WORK";
    private const int MaxAssetBytes = 32 * 1024 * 1024;
    internal static readonly Version Current = Assembly.GetExecutingAssembly().GetName().Version;

    [DataContract]
    private sealed class Release
    {
        [DataMember(Name = "tag_name")] public string Tag { get; set; }
        [DataMember(Name = "draft")] public bool Draft { get; set; }
        [DataMember(Name = "prerelease")] public bool Prerelease { get; set; }
        [DataMember(Name = "assets")] public Asset[] Assets { get; set; }
    }

    [DataContract]
    private sealed class Asset
    {
        [DataMember(Name = "name")] public string Name { get; set; }
        [DataMember(Name = "size")] public int Size { get; set; }
        [DataMember(Name = "digest")] public string Digest { get; set; }
        [DataMember(Name = "state")] public string State { get; set; }
        [DataMember(Name = "browser_download_url")] public string Url { get; set; }
    }

    private static Asset NewerAsset(byte[] body, Version current, out Version version)
    {
        Release release;
        using (var input = new MemoryStream(body))
            release = (Release)new DataContractJsonSerializer(typeof(Release)).ReadObject(input);
        version = null;
        if (release == null || release.Draft || release.Prerelease || release.Tag == null ||
            !Regex.IsMatch(release.Tag, @"\Av[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\z")) return null;
        version = Version.Parse(release.Tag.Substring(1) + ".0");
        if (version <= current) return null;
        string url = "https://github.com/" + Repository + "/releases/download/" + release.Tag + "/VPN_WORK.exe";
        var assets = (release.Assets ?? new Asset[0]).Where(a => a != null && a.Name == "VPN_WORK.exe").ToArray();
        if (assets.Length != 1 || assets[0].Url != url || assets[0].State != "uploaded" ||
            assets[0].Size <= 0 || assets[0].Size > MaxAssetBytes ||
            !Regex.IsMatch(assets[0].Digest ?? "", @"\Asha256:[0-9a-fA-F]{64}\z"))
            throw new InvalidDataException("В новом релизе нет подходящего VPN_WORK.exe с контрольной суммой.");
        return assets[0];
    }

    private static byte[] Download(Uri uri, bool asset, int limit)
    {
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        var clock = Stopwatch.StartNew();
        for (int hop = 0; hop <= 3; hop++) {
            string host = uri.Host;
            bool knownHost = asset
                ? host == "github.com" || host == "release-assets.githubusercontent.com" || host == "objects.githubusercontent.com"
                : host == "api.github.com";
            if (uri.Scheme != "https" || !uri.IsDefaultPort || uri.UserInfo.Length != 0 || !knownHost ||
                (hop > 0 && (!asset || host == "github.com")))
                throw new InvalidDataException("GitHub вернул неожиданный адрес обновления.");

            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.AllowAutoRedirect = false;
            request.UserAgent = "VPN_WORK/" + Current.ToString(3);
            request.Timeout = 4500;
            request.ReadWriteTimeout = 4500;
            if (!asset) request.Accept = "application/vnd.github+json";
            using (var response = (HttpWebResponse)request.GetResponse()) {
                int code = (int)response.StatusCode;
                if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                    Uri next;
                    if (!Uri.TryCreate(uri, response.Headers["Location"], out next)) throw new InvalidDataException("Нет адреса для скачивания.");
                    uri = next;
                    continue;
                }
                if (code != 200 || response.ContentLength > limit) throw new InvalidDataException("Неожиданный ответ при загрузке.");
                using (Stream input = response.GetResponseStream())
                using (var output = new MemoryStream()) {
                    var buffer = new byte[8192];
                    int count;
                    while ((count = input.Read(buffer, 0, buffer.Length)) != 0) {
                        if (output.Length + count > limit || clock.Elapsed.TotalSeconds > 15)
                            throw new IOException("Загрузка слишком большая или долгая.");
                        output.Write(buffer, 0, count);
                    }
                    return output.ToArray();
                }
            }
        }
        throw new IOException("Слишком много перенаправлений при загрузке.");
    }

    private static void VerifyAsset(byte[] bytes, int size, string digest)
    {
        using (var sha = SHA256.Create()) {
            string actual = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "");
            if (bytes.Length != size || !string.Equals(digest, "sha256:" + actual, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Контрольная сумма обновления не совпала.");
        }
    }

    internal static bool CheckAndStart(bool manual, Func<string, byte[]> resource)
    {
        if (manual) Console.WriteLine("Проверяю последний релиз GitHub…");
        Version version;
        Asset asset = NewerAsset(Download(new Uri("https://api.github.com/repos/" + Repository + "/releases/latest"), false, 256 * 1024), Current, out version);
        if (asset == null) { if (manual) Console.WriteLine("Новой стабильной версии нет."); return false; }
        Console.WriteLine("Найдена версия " + version.ToString(3) + ". Скачиваю обновление…");

        byte[] bytes = Download(new Uri(asset.Url), true, asset.Size);
        VerifyAsset(bytes, asset.Size, asset.Digest);
        string executable = Assembly.GetExecutingAssembly().Location;
        string pending = Path.Combine(Path.GetDirectoryName(executable), ".vpnwork-update-" + Guid.NewGuid().ToString("N") + ".exe");
        bool started = false;
        try {
            using (var file = new FileStream(pending, FileMode.CreateNew, FileAccess.Write)) file.Write(bytes, 0, bytes.Length);
            if (AssemblyName.GetAssemblyName(pending).Version != version)
                throw new InvalidDataException("Версия EXE не совпала с тегом релиза.");
            string helper = Encoding.UTF8.GetString(resource("InstallUpdate.ps1")).TrimStart('\uFEFF');
            int pid;
            using (Process self = Process.GetCurrentProcess()) pid = self.Id;
            string command = "& {\n" + helper + "\n} " + pid + " " + Literal(executable) + " " + Literal(pending) + " " + Literal(asset.Digest.Substring(7));
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(command));
            string powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            using (Process child = Process.Start(new ProcessStartInfo(powershell,
                "-NoProfile -NonInteractive -EncodedCommand " + encoded) { UseShellExecute = false, CreateNoWindow = true }))
                started = child != null;
            if (!started) throw new IOException("Не удалось запустить установщик обновления.");
            Console.WriteLine("Файл проверен. Программа перезапустится, уже без повторной проверки.");
            return true;
        } finally {
            if (!started && File.Exists(pending)) File.Delete(pending);
        }
    }

    private static string Literal(string value) { return "'" + value.Replace("'", "''") + "'"; }
}
