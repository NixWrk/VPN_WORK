using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

internal static class Program
{
    private static readonly string[] Files = {
        "split_tunnel.ps1", "gpt_vpn_guard.ps1", "gpt_vpn_filter.cs", "zotero_proxy.ps1"
    };
    private static readonly string InstallRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "VPN_WORK");
    private static readonly string DataRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VPN_WORK");

    private static int Main(string[] args)
    {
        try {
            if (!Console.IsOutputRedirected) Console.OutputEncoding = new UTF8Encoding(false);
            if (args.Length == 1 && args[0] == "--install-payload") {
                if (!IsElevated()) throw new UnauthorizedAccessException("Для установки нужны права администратора.");
                Install(InstallRoot);
                return 0;
            }
            if (args.Length == 1 && args[0] == "--verify") {
                foreach (string name in Files) Console.WriteLine(name + " " + Hash(ReadResource(name)));
                Console.WriteLine("Payload version: " + PayloadVersion());
                return 0;
            }
            if (args.Length == 1 && args[0] == "--help") {
                Console.WriteLine("VPN_WORK.exe             Open the Windows setup menu");
                Console.WriteLine("VPN_WORK.exe --verify    List the embedded components and their SHA-256 hashes");
                return 0;
            }
            if (args.Length != 0) { Console.Error.WriteLine("Unknown option. Use --help."); return 2; }
            return RunMenu();
        } catch (Exception error) {
            Console.Error.WriteLine(error.Message);
            if (args.Length == 0 && !Console.IsInputRedirected) {
                Console.WriteLine("Нажмите Enter, чтобы закрыть окно.");
                Console.ReadLine();
            }
            return 1;
        }
    }

    private static int RunMenu()
    {
        for (;;) {
            Console.WriteLine("\nVPN WORK — настройки сети Windows");
            Console.WriteLine(" 1  Установить или обновить обход VPN для выбранных сервисов");
            Console.WriteLine(" 2  Включить защиту ChatGPT и Codex и выбрать VPN");
            Console.WriteLine(" 3  Настроить локальный прокси Zotero");
            Console.WriteLine(" 4  Изменить список адресов обхода в Блокноте");
            Console.WriteLine(" 5  Изменить конфиг защиты ChatGPT и Codex");
            Console.WriteLine(" 6  Диагностика обхода VPN");
            Console.WriteLine(" 7  Состояние защиты ChatGPT и Codex");
            Console.WriteLine(" 8  Удалить обход VPN");
            Console.WriteLine(" 9  Снять защиту ChatGPT и Codex");
            Console.WriteLine("10  Удалить прокси Zotero");
            Console.WriteLine(" 0  Выход");
            Console.Write("Выберите действие: ");
            string selection = Console.ReadLine();
            if (selection == null || selection.Trim() == "0") return 0;
            if (selection.Trim().Length == 0) continue;

            try {
                int code;
                switch (selection.Trim()) {
                    case "1": code = RunScript("split_tunnel.ps1", "-Packaged"); break;
                    case "2": code = RunScript("gpt_vpn_guard.ps1", "-Packaged"); break;
                    case "3": code = RunScript("zotero_proxy.ps1", ""); break;
                    case "4": code = RunScript("split_tunnel.ps1", "-Packaged -EditConfig"); break;
                    case "5": EditGuardConfig(); code = 0; break;
                    case "6": code = RunScript("split_tunnel.ps1", "-Packaged -Diagnose"); break;
                    case "7": code = RunScript("gpt_vpn_guard.ps1", "-Packaged -Status"); break;
                    case "8": code = RunScript("split_tunnel.ps1", "-Packaged -Remove"); break;
                    case "9": code = RunScript("gpt_vpn_guard.ps1", "-Packaged -Remove"); break;
                    case "10": code = RunScript("zotero_proxy.ps1", "-Remove"); break;
                    default: Console.WriteLine("Нет такого пункта меню."); continue;
                }
                Console.WriteLine(code == 0 ? "Готово." : "Действие завершилось с кодом " + code + ".");
            } catch (Win32Exception error) {
                Console.WriteLine(error.NativeErrorCode == 1223 ? "Действие отменено." : error.Message);
            } catch (Exception error) { Console.WriteLine(error.Message); }
        }
    }

    private static void EditGuardConfig()
    {
        Directory.CreateDirectory(DataRoot);
        string file = Path.Combine(DataRoot, "gpt_vpn_guard.local.json");
        if (!File.Exists(file)) {
            using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                writer.Write("{\r\n  \"VpnAdapter\": \"\",\r\n  \"Programs\": []\r\n}\r\n");
        }
        using (Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "notepad.exe"),
            Quote(file)) { UseShellExecute = true })) { }
        Console.WriteLine("Настройки: " + file);
        Console.WriteLine("После сохранения заново включите защиту через пункт 2.");
    }

    private static int RunScript(string name, string arguments)
    {
        string directory = EnsureInstalled();
        string powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var start = new ProcessStartInfo(powershell, "-NoLogo -NoProfile -ExecutionPolicy Bypass -File " +
            Quote(Path.Combine(directory, name)) + " " + arguments) {
            UseShellExecute = false, WorkingDirectory = directory
        };
        using (Process child = Process.Start(start)) { child.WaitForExit(); return child.ExitCode; }
    }

    private static string EnsureInstalled()
    {
        string directory = Path.Combine(InstallRoot, PayloadVersion());
        if (!Directory.Exists(directory)) {
            if (IsElevated()) return Install(InstallRoot);
            Console.WriteLine("Первый запуск этой версии: Windows запросит разрешение на установку служебных файлов.");
            var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--install-payload") {
                UseShellExecute = true, Verb = "runas", WorkingDirectory = Environment.SystemDirectory
            };
            using (Process child = Process.Start(start)) {
                child.WaitForExit();
                if (child.ExitCode != 0) throw new IOException("Не удалось установить служебные файлы (код " + child.ExitCode + ").");
            }
        }
        VerifyInstalled(InstallRoot, directory);
        return directory;
    }

    private static bool IsElevated()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string Install(string root)
    {
        RejectReparsePoint(Path.GetDirectoryName(root));
        Directory.CreateDirectory(root);
        RejectReparsePoint(root);
        string directory = Path.Combine(root, PayloadVersion());
        if (!Directory.Exists(directory)) {
            string staging = Path.Combine(root, "staging-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(staging);
            try {
                foreach (string name in Files) {
                    byte[] bytes = ReadResource(name);
                    using (var stream = new FileStream(Path.Combine(staging, name), FileMode.CreateNew, FileAccess.Write))
                        stream.Write(bytes, 0, bytes.Length);
                }
                try { Directory.Move(staging, directory); }
                catch (IOException) { if (!Directory.Exists(directory)) throw; }
            } finally {
                if (Directory.Exists(staging)) {
                    foreach (string name in Files) File.Delete(Path.Combine(staging, name));
                    Directory.Delete(staging);
                }
            }
        }
        VerifyInstalled(root, directory);
        return directory;
    }

    private static void VerifyInstalled(string root, string directory)
    {
        RejectReparsePoint(Path.GetDirectoryName(root));
        RejectReparsePoint(root);
        RejectReparsePoint(directory);
        foreach (string name in Files) {
            string path = Path.Combine(directory, name);
            RejectReparsePoint(path);
            if (Hash(File.ReadAllBytes(path)) != Hash(ReadResource(name)))
                throw new IOException("Служебный файл не совпадает со сборкой: " + path);
        }
    }

    private static void RejectReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Служебный путь указывает на ссылку: " + path);
    }

    private static byte[] ReadResource(string name)
    {
        using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(name)) {
            if (input == null) throw new InvalidDataException("Missing embedded component: " + name);
            using (var output = new MemoryStream()) { input.CopyTo(output); return output.ToArray(); }
        }
    }

    private static string PayloadVersion()
    {
        var components = new StringBuilder();
        foreach (string name in Files) components.Append(name).Append(':').AppendLine(Hash(ReadResource(name)));
        return "payload-" + Hash(Encoding.ASCII.GetBytes(components.ToString()));
    }

    private static string Hash(byte[] bytes)
    {
        using (SHA256 sha = SHA256.Create())
            return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
    }

    private static string Quote(string value) { return "\"" + value + "\""; }
}
