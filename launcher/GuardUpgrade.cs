using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Xml;

internal static class GuardUpgrade
{
    private static readonly string[] GuardFiles = { "gpt_vpn_guard.ps1", "gpt_vpn_guard_watch.ps1", "gpt_vpn_filter.cs" };
    private const string TaskName = "VPN_WORK GPT VPN guard";
    private const string Watcher = "gpt_vpn_guard_watch.ps1";

    internal static bool IsRequired(string installRoot, Func<string, byte[]> resource)
    {
        string xml = ReadTaskXml();
        if (xml == null) {
            // 1.3.0 used guard-setup.lock even for explicit -NoStartup installs.
            if (File.Exists(Path.Combine(installRoot, "guard-setup.lock")) ||
                File.Exists(Path.Combine(installRoot, "guard-manual-only"))) return false;
            return GptVpnFilter.HasInstallation();
        }
        using (var user = WindowsIdentity.GetCurrent())
            return NeedsTaskUpgrade(xml, installRoot, user.User.Value, user.Name, resource);
    }

    private static string ReadTaskXml()
    {
        object service = null, folder = null, task = null;
        try {
            service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service", true));
            ((dynamic)service).Connect();
            folder = ((dynamic)service).GetFolder(@"\");
            try { task = ((dynamic)folder).GetTask(TaskName); }
            catch (COMException error) {
                if (error.ErrorCode == unchecked((int)0x80070002)) return null;
                throw;
            }
            return (string)((dynamic)task).Xml;
        } finally {
            if (task != null) Marshal.FinalReleaseComObject(task);
            if (folder != null) Marshal.FinalReleaseComObject(folder);
            if (service != null) Marshal.FinalReleaseComObject(service);
        }
    }

    private static bool NeedsTaskUpgrade(string xml, string root, string userSid, string userName, Func<string, byte[]> resource)
    {
        var task = new XmlDocument { XmlResolver = null };
        task.LoadXml(xml);
        var ns = new XmlNamespaceManager(task.NameTable);
        ns.AddNamespace("t", "http://schemas.microsoft.com/windows/2004/02/mit/task");
        if (TaskValue(task, ns, "t:Settings/t:Enabled") == "false") return false;
        var trigger = task.SelectSingleNode("/t:Task/t:Triggers/t:LogonTrigger[not(t:Enabled='false')]", ns);
        if (trigger == null) return false;
        string owner = TaskValue(task, ns, "t:Principals/t:Principal/t:UserId");
        if (!string.Equals(owner, userSid, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(owner, userName, StringComparison.OrdinalIgnoreCase)) return false;

        string powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        string command = TaskValue(task, ns, "t:Actions/t:Exec/t:Command");
        string directory = TaskValue(task, ns, "t:Actions/t:Exec/t:WorkingDirectory");
        string arguments = TaskValue(task, ns, "t:Actions/t:Exec/t:Arguments");
        if (!string.Equals(command, powershell, StringComparison.OrdinalIgnoreCase) || !Path.IsPathRooted(directory) ||
            arguments.IndexOf("-File \"" + Path.Combine(directory, Watcher) + "\"", StringComparison.OrdinalIgnoreCase) < 0)
            return false;

        directory = Path.GetFullPath(directory);
        if (!string.Equals(Path.GetDirectoryName(directory), root, StringComparison.OrdinalIgnoreCase) ||
            !Regex.IsMatch(Path.GetFileName(directory), @"\Aguard-[a-f0-9]{64}\z", RegexOptions.IgnoreCase)) return true;
        if (!Directory.Exists(directory) || IsReparsePoint(root) || IsReparsePoint(directory)) return true;
        foreach (string name in GuardFiles) {
            string path = Path.Combine(directory, name);
            if (!File.Exists(path) || IsReparsePoint(path) || !File.ReadAllBytes(path).SequenceEqual(resource(name))) return true;
        }
        return false;
    }

    private static bool IsReparsePoint(string path)
    {
        return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0;
    }

    private static string TaskValue(XmlDocument task, XmlNamespaceManager ns, string path)
    {
        XmlNode value = task.SelectSingleNode("/t:Task/" + path, ns);
        return value == null ? "" : value.InnerText.Trim();
    }
}
