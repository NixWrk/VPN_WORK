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
        "split_tunnel.ps1", "gpt_vpn_guard.ps1", "gpt_vpn_guard_watch.ps1", "gpt_vpn_filter.cs", "zotero_proxy.ps1"
    };
    private static readonly string InstallRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "VPN_WORK");
    private static readonly string DataRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VPN_WORK");
    private static readonly string NoAutoUpdate = Path.Combine(DataRoot, "disable-auto-update");

    private static int Main(string[] args)
    {
        try {
            if (!Console.IsOutputRedirected) Console.OutputEncoding = new UTF8Encoding(false);
            if (args.Length == 1 && args[0] == "--install-payload") {
                if (!IsElevated()) throw new UnauthorizedAccessException("Для установки нужны права администратора.");
                Install(InstallRoot);
                return 0;
            }
            if (args.Length == 1 && args[0] == "--migrate-guard") {
                if (!IsElevated()) throw new UnauthorizedAccessException("Для переноса защиты нужны права администратора.");
                if (!GuardUpgrade.IsRequired(InstallRoot, ReadResource)) return 3;
                return RunInstalledScript(Install(InstallRoot), "gpt_vpn_guard.ps1", "-Packaged -Migrate");
            }
            if (args.Length == 1 && args[0] == "--verify") {
                foreach (string name in Files) Console.WriteLine(name + " " + Hash(ReadResource(name)));
                Console.WriteLine("Payload version: " + PayloadVersion());
                return 0;
            }
            if (args.Length == 1 && args[0] == "--help") {
                Console.WriteLine("VPN_WORK.exe             Open the Windows setup menu");
                Console.WriteLine("VPN_WORK.exe --verify    List the embedded components and their SHA-256 hashes");
                Console.WriteLine("VPN_WORK.exe --version   Print the release version");
                Console.WriteLine("VPN_WORK.exe --no-update Skip the startup update check once");
                return 0;
            }
            if (args.Length == 1 && args[0] == "--version") { Console.WriteLine(Updater.Current.ToString(3)); return 0; }
            bool skipUpdate = args.Length == 1 && (args[0] == "--no-update" || args[0] == "--update-failed");
            if (args.Length != 0 && !skipUpdate) { Console.Error.WriteLine("Unknown option. Use --help."); return 2; }
            if (skipUpdate && args[0] == "--update-failed")
                Console.WriteLine("Обновление не установилось. Сохранена предыдущая версия.");
            if (!skipUpdate && !Console.IsInputRedirected && !File.Exists(NoAutoUpdate) && !IsElevated() && TryUpdate(false)) return 0;
            if (Environment.UserInteractive && !Console.IsInputRedirected) UpgradeGuardAtStartup();
            return RunMenu(RunScript);
        } catch (Exception error) {
            Console.Error.WriteLine(error.Message);
            if (args.Length == 0 && !Console.IsInputRedirected) {
                Console.WriteLine("Нажмите Enter, чтобы закрыть окно.");
                Console.ReadLine();
            }
            return 1;
        }
    }

    private static int RunMenu(Func<string, string, int> run)
    {
        for (;;) {
            Console.WriteLine("\nVPN WORK " + Updater.Current.ToString(3));
            Console.WriteLine("1  Автоматическая настройка — применить рекомендуемые настройки");
            Console.WriteLine("2  Ручная настройка — изменить отдельные функции или настройки обновлений");
            Console.WriteLine("0  Выход");
            switch (ReadChoice()) {
                case "1": RunAutomatic(run); break;
                case "2": if (RunManual(run)) return 0; break;
                case "0": return 0;
                default: UnknownChoice(); break;
            }
        }
    }

    private static void RunAutomatic(Func<string, string, int> run)
    {
        Console.WriteLine("\nАвтоматическая настройка");
        Console.WriteLine("• Избранные рабочие сайты, PubMed и Element будут работать мимо VPN.");
        Console.WriteLine("• ChatGPT и Codex смогут выходить в интернет только через разрешённый VPN.");
        Console.WriteLine("  Используется утверждённая настройка. По умолчанию VPN определяется по маршрутам Windows.");
        Console.WriteLine("  Защита восстановит разрешения при входе в Windows и подключении VPN.");
        Console.WriteLine("• Прокси Zotero обновится, только если уже настроен и Zotero закрыт.");
        if (!Confirm("1  Применить настройки    0  Назад")) return;
        int routes = RunAction(run, "split_tunnel.ps1", "-Packaged");
        int guard = routes == 1223 ? 1223 : RunAction(run, "gpt_vpn_guard.ps1", "-Packaged -Guided");
        int zotero = guard == 1223 ? 1223 : RunAction(run, "zotero_proxy.ps1", "-Automatic");
        Console.WriteLine("\nРезультат автоматической настройки:");
        Console.WriteLine("  Обход VPN: " + Result(routes));
        Console.WriteLine("  Защита ChatGPT и Codex: " + Result(guard));
        Console.WriteLine("  Прокси Zotero: " + Result(zotero));
        if (zotero == 3) Console.WriteLine("    Новый прокси можно включить вручную, если Zotero плохо синхронизируется.");
    }

    private static bool RunManual(Func<string, string, int> run)
    {
        for (;;) {
            Console.WriteLine("\nРучная настройка");
            Console.WriteLine("1  Обход VPN — выбранные сайты и приложения работают напрямую");
            Console.WriteLine("2  ChatGPT и Codex — блокировка интернета вне VPN");
            Console.WriteLine("3  Zotero — исправление проблем с синхронизацией через локальный прокси");
            Console.WriteLine("4  Обновления программы — включить, отключить или проверить сейчас");
            Console.WriteLine("5  Прокси для браузера — открыть сайты .ru и .рф напрямую с первого соединения");
            Console.WriteLine("0  Назад");
            switch (ReadChoice()) {
                case "1": RoutesMenu(run); break;
                case "2": GuardMenu(run); break;
                case "3": ZoteroMenu(run); break;
                case "4": if (UpdatesMenu(NoAutoUpdate, () => TryUpdate(true))) return true; break;
                case "5": BrowserProxyMenu(); break;
                case "0": return false;
                default: UnknownChoice(); break;
            }
        }
    }

    private static void BrowserProxyMenu()
    {
        for (;;) {
            Console.WriteLine("\nПрокси для браузера");
            Console.WriteLine("Открывает отдельный профиль. Сайты .ru и .рф используют прямой IPv4 или IPv6, если он доступен.");
            Console.WriteLine("1  Открыть Microsoft Edge с прокси");
            Console.WriteLine("2  Открыть Google Chrome с прокси");
            Console.WriteLine("0  Назад");
            string choice = ReadChoice();
            if (choice == "0") return;
            if (choice != "1" && choice != "2") { UnknownChoice(); continue; }
            if (IsElevated()) {
                Console.WriteLine("Для прокси и браузера запустите VPN_WORK обычным двойным кликом без прав администратора.");
                continue;
            }
            try { BrowserProxy.OpenBrowser(DataRoot, choice == "1"); }
            catch (Exception error) { Console.WriteLine("Прокси не запущен. " + error.Message); }
        }
    }

    private static void RoutesMenu(Func<string, string, int> run)
    {
        for (;;) {
            Console.WriteLine("\nОбход VPN");
            Console.WriteLine("1  Применить обход — обновить прямой доступ к рабочим сервисам и вашим адресам");
            Console.WriteLine("2  Свои адреса — открыть список в Блокноте (один адрес на строку)");
            Console.WriteLine("3  Проверить список — найти ошибки в файле без изменения сети");
            Console.WriteLine("4  Диагностика — показать шлюз, DNS и состояние фоновой задачи");
            Console.WriteLine("5  Убрать обход — удалить добавленные маршруты и DNS-правила, сохранить список");
            Console.WriteLine("0  Назад");
            switch (ReadChoice()) {
                case "1": RunAction(run, "split_tunnel.ps1", "-Packaged"); break;
                case "2":
                    if (RunAction(run, "split_tunnel.ps1", "-Packaged -EditConfig") == 0)
                        Console.WriteLine("После сохранения выберите «Применить обход».");
                    break;
                case "3": RunAction(run, "split_tunnel.ps1", "-Packaged -CheckConfig"); break;
                case "4": RunAction(run, "split_tunnel.ps1", "-Packaged -Diagnose"); break;
                case "5":
                    if (Confirm("1  Убрать обход VPN    0  Назад")) RunAction(run, "split_tunnel.ps1", "-Packaged -Remove");
                    break;
                case "0": return;
                default: UnknownChoice(); break;
            }
        }
    }

    private static void GuardMenu(Func<string, string, int> run)
    {
        for (;;) {
            Console.WriteLine("\nЗащита ChatGPT и Codex");
            Console.WriteLine("1  Включить защиту — определить VPN по маршрутам Windows");
            Console.WriteLine("2  Выбрать VPN вручную — показать все интерфейсы и выбрать туннели");
            Console.WriteLine("3  Дополнительные программы — добавить, например, отдельный браузер целиком");
            Console.WriteLine("4  Проверить состояние — показать правила, фоновую задачу и интерфейсы");
            Console.WriteLine("5  Заблокировать весь внешний доступ — до смены режима защиты");
            Console.WriteLine("6  Снять защиту — снова разрешить подключение без VPN");
            Console.WriteLine("0  Назад");
            switch (ReadChoice()) {
                case "1": RunAction(run, "gpt_vpn_guard.ps1", "-Packaged -Auto"); break;
                case "2": RunAction(run, "gpt_vpn_guard.ps1", "-Packaged -Guided -ChooseVpn"); break;
                case "3": RunAction((name, args) => { EditGuardConfig(); return 0; }, "", ""); break;
                case "4": RunAction(run, "gpt_vpn_guard.ps1", "-Packaged -Status"); break;
                case "5":
                    if (Confirm("1  Заблокировать весь внешний доступ этих приложений    0  Назад"))
                        RunAction(run, "gpt_vpn_guard.ps1", "-Packaged -BlockAll");
                    break;
                case "6":
                    if (Confirm("1  Снять защиту    0  Назад")) RunAction(run, "gpt_vpn_guard.ps1", "-Packaged -Remove");
                    break;
                case "0": return;
                default: UnknownChoice(); break;
            }
        }
    }

    private static void ZoteroMenu(Func<string, string, int> run)
    {
        for (;;) {
            Console.WriteLine("\nПрокси Zotero");
            Console.WriteLine("Нужен только при проблемах с синхронизацией. Перед изменениями закройте Zotero.");
            Console.WriteLine("1  Настроить или обновить локальный прокси");
            Console.WriteLine("2  Убрать прокси — восстановить предыдущие настройки Zotero");
            Console.WriteLine("0  Назад");
            switch (ReadChoice()) {
                case "1": RunAction(run, "zotero_proxy.ps1", ""); break;
                case "2":
                    if (Confirm("1  Убрать прокси Zotero    0  Назад")) RunAction(run, "zotero_proxy.ps1", "-Remove");
                    break;
                case "0": return;
                default: UnknownChoice(); break;
            }
        }
    }

    private static bool UpdatesMenu(string preference, Func<bool> checkNow)
    {
        for (;;) {
            bool enabled = !File.Exists(preference);
            Console.WriteLine("\nОбновления программы");
            Console.WriteLine("Текущая версия: " + Updater.Current.ToString(3) + ". Автообновление: " + (enabled ? "включено" : "выключено") + ".");
            Console.WriteLine("1  " + (enabled ? "Отключить" : "Включить") + " проверку и установку обновлений при запуске");
            Console.WriteLine("2  Проверить сейчас — установить более новую версию из GitHub, если она есть");
            Console.WriteLine("0  Назад");
            switch (ReadChoice()) {
                case "1":
                    try {
                        if (enabled) { Directory.CreateDirectory(Path.GetDirectoryName(preference)); File.WriteAllText(preference, ""); }
                        else File.Delete(preference);
                        Console.WriteLine(enabled ? "Автообновление отключено." : "Автообновление включено.");
                    } catch (Exception error) { Console.WriteLine(error.Message); }
                    break;
                case "2": if (checkNow()) return true; break;
                case "0": return false;
                default: UnknownChoice(); break;
            }
        }
    }

    private static bool TryUpdate(bool manual)
    {
        try {
            if (IsElevated()) { if (manual) Console.WriteLine("Для обновления запустите программу без прав администратора."); return false; }
            return Updater.CheckAndStart(manual, ReadResource);
        } catch (Exception error) {
            Console.WriteLine("Не удалось обновиться: " + error.Message);
            Console.WriteLine("Можно продолжать работу с текущей версией.");
            return false;
        }
    }

    private static string ReadChoice()
    {
        Console.Write("Выберите номер: ");
        string answer = Console.ReadLine();
        return answer == null ? "0" : answer.Trim();
    }

    private static bool Confirm(string options) { Console.WriteLine(options); return ReadChoice() == "1"; }
    private static void UnknownChoice() { Console.WriteLine("Введите номер из меню."); }
    private static string Result(int code) { return code == 0 ? "готово" : code == 3 ? "пропущено" : code == 1223 ? "отменено" : "не удалось (код " + code + ")"; }

    private static int RunAction(Func<string, string, int> run, string name, string arguments)
    {
        int code;
        try { code = run(name, arguments); }
        catch (Win32Exception error) { code = error.NativeErrorCode; if (code != 1223) Console.WriteLine(error.Message); }
        catch (Exception error) { Console.WriteLine(error.Message); code = 1; }
        Console.WriteLine("Результат: " + Result(code) + ".");
        return code;
    }

    private static void EditGuardConfig()
    {
        Directory.CreateDirectory(DataRoot);
        string file = Path.Combine(DataRoot, "gpt_vpn_guard.local.json");
        if (!File.Exists(file)) {
            using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write))
            using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
                writer.Write("{\r\n  \"Mode\": \"auto\",\r\n  \"VpnAdapters\": [],\r\n  \"Programs\": []\r\n}\r\n");
        }
        using (Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "notepad.exe"),
            Quote(file)) { UseShellExecute = true })) { }
        Console.WriteLine("Настройки: " + file);
        Console.WriteLine("Режим auto проверяет маршруты Windows, adapters использует VpnAdapters, blockall блокирует внешний доступ.");
        Console.WriteLine("В VpnAdapters укажите имена или GUID из Get-NetAdapter. В Programs — полные пути к .exe.");
        Console.WriteLine("В JSON обратная косая черта записывается как \\\\.");
        Console.WriteLine("Весь добавленный браузер будет работать только через VPN, включая остальные вкладки.");
        Console.WriteLine("После сохранения снова включите защиту.");
    }

    private static int RunScript(string name, string arguments)
    {
        return RunInstalledScript(EnsureInstalled(), name, arguments);
    }

    private static int RunInstalledScript(string directory, string name, string arguments)
    {
        string powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var start = new ProcessStartInfo(powershell, "-NoLogo -NoProfile -ExecutionPolicy Bypass -File " +
            Quote(Path.Combine(directory, name)) + " " + arguments) {
            UseShellExecute = false, WorkingDirectory = directory
        };
        using (Process child = Process.Start(start)) { child.WaitForExit(); return child.ExitCode; }
    }

    private static void UpgradeGuardAtStartup()
    {
        try {
            if (!GuardUpgrade.IsRequired(InstallRoot, ReadResource)) return;
            Console.WriteLine("Переношу уже включённую защиту ChatGPT и Codex в новую версию.");
            int code;
            if (IsElevated()) {
                code = RunInstalledScript(Install(InstallRoot), "gpt_vpn_guard.ps1", "-Packaged -Migrate");
            } else {
                Console.WriteLine("Подтвердите запрос Windows на обновление фоновой задачи.");
                var start = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location, "--migrate-guard") {
                    UseShellExecute = true, Verb = "runas", WorkingDirectory = Environment.SystemDirectory
                };
                using (Process child = Process.Start(start)) { child.WaitForExit(); code = child.ExitCode; }
            }
            if (code == 0) Console.WriteLine("Защита перенесена. Автовосстановление при входе в Windows включено.");
            else if (code != 3) Console.WriteLine("Не удалось перенести защиту. Код " + code + ".");
        } catch (Win32Exception error) {
            if (error.NativeErrorCode == 1223) Console.WriteLine("Перенос защиты отложен до следующего запуска VPN_WORK.");
            else Console.WriteLine("Не удалось перенести защиту. " + error.Message);
        } catch (Exception error) {
            Console.WriteLine("Не удалось проверить или перенести защиту. " + error.Message);
        }
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
