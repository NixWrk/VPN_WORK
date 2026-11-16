<#
.SYNOPSIS
Исправляет синхронизацию Zotero при неверном выборе адреса ZeroTier.

.DESCRIPTION
Один раз настраивает профили Zotero на SOCKS5 127.0.0.1:27654 и регистрирует
proxy как задачу текущего пользователя с автоматическим перезапуском при сбое.
URL, логины и протокол WebDAV не меняются; TLS остаётся сквозным. На других
компьютерах ничего менять не нужно.

.PARAMETER Remove
Удаляет proxy и восстанавливает прежние network.proxy.* настройки. Zotero
должен быть закрыт.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\zotero_proxy.ps1

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\zotero_proxy.ps1 -Remove
#>

[CmdletBinding()]
param(
    [switch]$Remove,
    [Parameter(DontShow = $true)][switch]$Worker,
    [Parameter(DontShow = $true)][int]$Port = 27654
)

$StateFile = Join-Path $env:LOCALAPPDATA "zotero_proxy_state.json"
$LegacyRunKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$TaskName = "ZoteroLocalProxy"
$Begin = "// BEGIN zotero_proxy managed block"
$End = "// END zotero_proxy managed block"
$ProxyPref = '^\s*user_pref\("network\.proxy\.(?:type|socks|socks_port|socks_version|socks_remote_dns)",.*\);\s*$'

function Write-Utf8([string]$Path, [AllowEmptyString()][string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, [Text.UTF8Encoding]::new($false))
}

function Get-ZoteroProfiles {
    $root = Join-Path $env:APPDATA "Zotero\Zotero"
    $ini = Join-Path $root "profiles.ini"
    if (-not (Test-Path -LiteralPath $ini)) { return @() }
    $iniText = [IO.File]::ReadAllText($ini) -replace "`r", ''

    $profiles = foreach ($section in ($iniText -split '(?m)(?=^\[)')) {
        if ($section -notmatch '(?m)^\[Profile\d+\]') { continue }
        $pathMatch = [regex]::Match($section, '(?m)^Path=(.+)$')
        if (-not $pathMatch.Success) { continue }
        $path = $pathMatch.Groups[1].Value.Trim() -replace '/', '\'
        if ($section -notmatch '(?m)^IsRelative=0$') { $path = Join-Path $root $path }
        if (Test-Path -LiteralPath $path) { [IO.Path]::GetFullPath($path) }
    }
    return @($profiles | Select-Object -Unique)
}

function Remove-Block([AllowEmptyString()][string]$Text) {
    $pattern = '(?ms)^' + [regex]::Escape($Begin) + '.*?^' + [regex]::Escape($End) + '\r?\n?'
    return [regex]::Replace($Text, $pattern, '')
}

function Get-Block([int]$ProxyPort) {
    return @"
$Begin
user_pref("network.proxy.type", 1);
user_pref("network.proxy.socks", "127.0.0.1");
user_pref("network.proxy.socks_port", $ProxyPort);
user_pref("network.proxy.socks_version", 5);
user_pref("network.proxy.socks_remote_dns", true);
$End
"@
}

function Get-ProxyProcess([int]$ProxyPort) {
    $connection = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $ProxyPort `
        -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $connection) { return $null }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($connection.OwningProcess)" `
        -ErrorAction SilentlyContinue
    if ($process.CommandLine -match [regex]::Escape($PSCommandPath) -and
        $process.CommandLine -match '(?i)-Worker') { return $process }
    return $null
}

function Remove-ProxyTask {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { return }
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
}

function Register-ProxyTask([int]$ProxyPort) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }

    $proxy = Get-ProxyProcess $ProxyPort
    if ($proxy) {
        Stop-Process -Id $proxy.ProcessId -Force
        Wait-Process -Id $proxy.ProcessId -Timeout 10 -ErrorAction SilentlyContinue
    }

    $powerShellExe = Join-Path $PSHOME "powershell.exe"
    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Worker -Port $ProxyPort"
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute $powerShellExe -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
    $repeatTrigger = New-ScheduledTaskTrigger `
        -Once `
        -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet `
        -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $action `
        -Trigger @($trigger, $repeatTrigger) `
        -Principal $principal `
        -Settings $settings `
        -Description "Local SOCKS5 relay for Zotero with automatic restart" `
        -Force | Out-Null

    # Migrate installations made by the previous version of this script.
    Remove-ItemProperty -Path $LegacyRunKey -Name $TaskName -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName $TaskName
    foreach ($i in 1..40) {
        if (Get-ProxyProcess $ProxyPort) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "Scheduled proxy did not start on 127.0.0.1:$ProxyPort"
}

function Start-Worker([int]$ListenPort) {
    $code = @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

public static class LocalSocks5 {
    public static void Run(int port) {
        var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();
        while (true) {
            var client = listener.AcceptTcpClient();
            Task.Run(() => Relay(client));
        }
    }

    static async Task Relay(TcpClient client) {
        TcpClient remote = null;
        try {
            var local = client.GetStream();
            var hello = await Read(local, 2);
            if (hello[0] != 5) return;
            var methods = await Read(local, hello[1]);
            bool noAuth = Array.IndexOf(methods, (byte)0) >= 0;
            await local.WriteAsync(new byte[] { 5, noAuth ? (byte)0 : (byte)255 }, 0, 2);
            if (!noAuth) return;

            var request = await Read(local, 4);
            if (request[0] != 5 || request[1] != 1) return;
            string host;
            if (request[3] == 1) host = new IPAddress(await Read(local, 4)).ToString();
            else if (request[3] == 3) host = Encoding.ASCII.GetString(await Read(local, (await Read(local, 1))[0]));
            else if (request[3] == 4) host = new IPAddress(await Read(local, 16)).ToString();
            else return;

            var p = await Read(local, 2);
            remote = new TcpClient();
            await remote.ConnectAsync(host, (p[0] << 8) | p[1]);
            await local.WriteAsync(new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 }, 0, 10);
            var network = remote.GetStream();
            await Task.WhenAny(local.CopyToAsync(network), network.CopyToAsync(local));
        }
        catch { }
        finally {
            if (remote != null) remote.Close();
            client.Close();
        }
    }

    static async Task<byte[]> Read(Stream stream, int length) {
        var data = new byte[length];
        for (int offset = 0; offset < length;) {
            int count = await stream.ReadAsync(data, offset, length - offset);
            if (count == 0) throw new EndOfStreamException();
            offset += count;
        }
        return data;
    }
}
'@
    Add-Type -TypeDefinition $code -Language CSharp -ErrorAction Stop
    [LocalSocks5]::Run($ListenPort)
}

if ($Worker) {
    try { Start-Worker $Port } catch {
        Write-Error $_
        exit 1
    }
    exit
}

if ($Remove) {
    if (Get-Process zotero -ErrorAction SilentlyContinue) {
        throw "Close Zotero before removing the proxy"
    }
    $state = $null
    if (Test-Path -LiteralPath $StateFile) {
        $state = Get-Content -LiteralPath $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($profile in @($state.Profiles)) {
            $userJs = Join-Path $profile.Directory "user.js"
            if ($profile.UserJsExisted) {
                [IO.File]::WriteAllBytes($userJs, [Convert]::FromBase64String($profile.UserJsBase64))
            } else { Remove-Item -LiteralPath $userJs -Force -ErrorAction SilentlyContinue }

            $prefsJs = Join-Path $profile.Directory "prefs.js"
            if (Test-Path -LiteralPath $prefsJs) {
                $prefs = [IO.File]::ReadAllText($prefsJs)
                $prefs = [regex]::Replace($prefs, $ProxyPref + '\r?\n?', '', 'Multiline').TrimEnd()
                if ($profile.OriginalPrefs) { $prefs += "`r`n" + (@($profile.OriginalPrefs) -join "`r`n") }
                Write-Utf8 $prefsJs ($prefs + "`r`n")
            }
        }
    }
    Remove-ProxyTask
    $proxyPort = if ($state) { [int]$state.Port } else { $Port }
    $proxy = Get-ProxyProcess $proxyPort
    if ($proxy) { Stop-Process -Id $proxy.ProcessId -Force }
    Remove-ItemProperty -Path $LegacyRunKey -Name $TaskName -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
    Write-Host "Removed. Previous Zotero proxy settings restored."
    exit
}

$oldState = if (Test-Path -LiteralPath $StateFile) {
    Get-Content -LiteralPath $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
}
$oldByPath = @{}
foreach ($record in @($oldState.Profiles)) { $oldByPath[[string]$record.Directory] = $record }

$records = foreach ($directory in Get-ZoteroProfiles) {
    $userJs = Join-Path $directory "user.js"
    $userJsExisted = Test-Path -LiteralPath $userJs
    [byte[]]$originalBytes = @()
    if ($userJsExisted) { $originalBytes = [IO.File]::ReadAllBytes($userJs) }
    $content = [Text.Encoding]::UTF8.GetString($originalBytes)
    $old = $oldByPath[$directory]
    if (-not $old -and (Remove-Block $content) -match $ProxyPref) {
        Write-Warning "Custom proxy settings found; skipped profile $directory"
        continue
    }

    $prefsJs = Join-Path $directory "prefs.js"
    $originalPrefs = if ($old) { @($old.OriginalPrefs) } elseif (Test-Path -LiteralPath $prefsJs) {
        @([regex]::Matches([IO.File]::ReadAllText($prefsJs), $ProxyPref, 'Multiline') | ForEach-Object { $_.Value.Trim() })
    } else { @() }
    $prefix = (Remove-Block $content).TrimEnd()
    if ($prefix) { $prefix += "`r`n`r`n" }
    Write-Utf8 $userJs ($prefix + (Get-Block $Port))

    [ordered]@{
        Directory = $directory
        UserJsExisted = if ($old) { [bool]$old.UserJsExisted } else { $userJsExisted }
        UserJsBase64 = if ($old) { [string]$old.UserJsBase64 } else { [Convert]::ToBase64String($originalBytes) }
        OriginalPrefs = $originalPrefs
    }
}

if (-not $records) { throw "No Zotero profile was configured" }
Register-ProxyTask $Port
[ordered]@{ Version = 1; Port = $Port; Profiles = @($records) } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StateFile -Encoding UTF8

Write-Host "Configured $(@($records).Count) Zotero profile(s). The scheduled proxy restarts automatically after failure. Restart Zotero."
