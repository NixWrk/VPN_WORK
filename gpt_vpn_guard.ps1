<#
.SYNOPSIS
Protects ChatGPT, Codex and explicitly selected Windows executables with a VPN-only network policy.
.DESCRIPTION
The automatic mode uses Windows tunnel adapter types and active default, split-default
or split-tunnel public routes. Select other trusted VPN interfaces explicitly. Blocking
rules persist across restarts. A task refreshes the permits at logon and when the active
network changes.
.PARAMETER VpnAdapter
Optional exact adapter name(s) or GUID(s). Explicit choices are saved by GUID.
.PARAMETER Program
Additional absolute .exe path(s), e.g. a browser dedicated to ChatGPT.
The entire executable is protected, including its other profiles and tabs.
.PARAMETER BlockAll
Install the policy without any VPN exception. Local loopback still works.
.PARAMETER Auto
Use active default routes on Windows tunnel interfaces.
.PARAMETER NoStartup
Apply the current rules and remove the background task.
.PARAMETER Plan
Show the selected tunnels and protected applications without changing WFP,
registering tasks or requesting elevation.
.PARAMETER Status
Show the installed WFP filters and the background task. Requires an Administrator terminal.
.PARAMETER Remove
Remove this script's protection and its background task. Requires Administrator permissions.
#>
[CmdletBinding()]
param(
    [string[]]$VpnAdapter,
    [string[]]$Program,
    [switch]$BlockAll,
    [switch]$Auto,
    [switch]$NoStartup,
    [switch]$Plan,
    [switch]$Status,
    [switch]$Remove,
    [Parameter(DontShow = $true)][switch]$Reapply,
    [Parameter(DontShow = $true)][switch]$Migrate,
    [Parameter(DontShow = $true)][switch]$Guided,
    [Parameter(DontShow = $true)][switch]$ChooseVpn,
    [Parameter(DontShow = $true)][switch]$Packaged,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$ExecutableNames = @('ChatGPT.exe', 'Codex.exe', 'Codex Web GPT.exe',
    'codex-code-mode-host.exe', 'codex-computer-use-swift.exe',
    'codex-windows-sandbox.exe', 'codex-windows-sandbox-service.exe')
$PackageFamilies = @('OpenAI.Codex_2p2nqsd0c76g0', 'OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0')
$TaskName = 'VPN_WORK GPT VPN guard'
$RuntimeRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'VPN_WORK'
$RuntimeFiles = @('gpt_vpn_guard.ps1', 'gpt_vpn_guard_watch.ps1', 'gpt_vpn_filter.cs')
$PolicyFileName = 'guard-policy.json'
$ManualOnlyPath = Join-Path $RuntimeRoot 'guard-manual-only'
$LegacySetupLockPath = Join-Path $RuntimeRoot 'guard-setup.lock'
$configDirectory = if ($Packaged) { Join-Path $env:LOCALAPPDATA 'VPN_WORK' } else { $PSScriptRoot }
$ConfigPath = Join-Path $configDirectory 'gpt_vpn_guard.local.json'

$NonVpnAdapterDescriptions = @(
    'Hyper-V', 'vEthernet', 'Virtual Switch', 'Loopback', 'Bluetooth', 'Wi-Fi Direct',
    'Kernel Debug', 'Teredo', '6to4', 'IP-HTTPS', 'Pseudo-Interface', 'RAS Async',
    'ISATAP', 'Host[- ]Only', 'VMware Network Adapter', '^WAN Miniport \((IP|IPv6|Network Monitor|PPPOE)\)$'
)

function Get-VpnAdapterExclusion {
    param([object]$Adapter)
    if ($Adapter.Name -match 'ZeroTier' -or $Adapter.InterfaceDescription -match 'ZeroTier') { return 'виртуальная локальная сеть ZeroTier' }
    if ($Adapter.HardwareInterface -eq $true) { return 'физический адаптер' }
    if (-not $Adapter.InterfaceGuid -or $false -ne $Adapter.HardwareInterface) { return 'тип или GUID интерфейса неизвестен' }
    foreach ($pattern in $NonVpnAdapterDescriptions) {
        if ($Adapter.InterfaceDescription -match $pattern -or $Adapter.Name -match $pattern) {
            return 'служебный интерфейс или виртуальная локальная сеть'
        }
    }
}

function Test-VpnPathAdapter {
    param([object]$Adapter)
    return -not (Get-VpnAdapterExclusion $Adapter)
}

function Get-VpnPathAdapters {
    param([object[]]$Adapters)
    return @($Adapters | Where-Object { Test-VpnPathAdapter -Adapter $_ } | Sort-Object Name)
}

function Test-PublicRoutePrefix {
    param([string]$Prefix)
    if ($Prefix -notmatch '^([^/]+)/(\d{1,3})$') { return $false }
    $address = $null
    if (-not [Net.IPAddress]::TryParse($matches[1], [ref]$address)) { return $false }
    $length = [int]$matches[2]
    $bytes = $address.GetAddressBytes()
    if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
        # Exclude default and half routes: they are handled by the default-route
        # check. Only specific public prefixes indicate a split tunnel.
        if ($length -lt 2 -or $length -gt 32) { return $false }
        if ($bytes[0] -eq 0 -or $bytes[0] -eq 10 -or $bytes[0] -eq 127 -or $bytes[0] -ge 224) { return $false }
        if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $false }
        if ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) { return $false }
        if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $false }
        if ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127) { return $false }
        return $true
    }
    if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($length -lt 2 -or $length -gt 128) { return $false }
        if ($address.Equals([Net.IPAddress]::IPv6Loopback)) { return $false }
        if (($bytes[0] -band 0xFE) -eq 0xFC) { return $false }
        if ($bytes[0] -eq 0xFE -and ($bytes[1] -band 0xC0) -eq 0x80) { return $false }
        if ($bytes[0] -eq 0xFF) { return $false }
        return $true
    }
    return $false
}

function Get-AutomaticVpnAdapters {
    param([object[]]$Adapters, [object[]]$Routes)

    # IANA ifTypes ppp(23), propVirtual(53), tunnel(131). Virtual Ethernet and
    # overlays still require an explicit choice, even if they advertise a default.
    $candidates = @(Get-VpnPathAdapters $Adapters | Where-Object {
        $_.Status -eq 'Up' -and $_.InterfaceType -in @(23, 53, 131)
    })
    $indices = @(foreach ($family in @('IPv4', 'IPv6')) {
        $default = if ($family -eq 'IPv4') { '0.0.0.0/0' } else { '::/0' }
        $halves = if ($family -eq 'IPv4') { @('0.0.0.0/1', '128.0.0.0/1') } else { @('::/1', '8000::/1') }
        $used = @(foreach ($half in $halves) {
            $ordered = @($Routes | Where-Object DestinationPrefix -in @($half, $default) |
                Sort-Object @{ Expression = { if ($_.DestinationPrefix -eq $half) { 0 } else { 1 } } },
                    @{ Expression = { [long]$_.RouteMetric + [long]$_.InterfaceMetric } })
            if (-not $ordered.Count) { continue }
            $first = $ordered[0]
            $cost = [long]$first.RouteMetric + [long]$first.InterfaceMetric
            $best = @($ordered | Where-Object { $_.DestinationPrefix -eq $first.DestinationPrefix -and
                ([long]$_.RouteMetric + [long]$_.InterfaceMetric) -eq $cost } |
                Select-Object -ExpandProperty InterfaceIndex -Unique)
            if ($best.Count -eq 1) { $best[0] }
        })
        if ($used.Count -eq 2 -and $used[0] -eq $used[1]) { $used[0] }
    })
    # A split-tunnel VPN may publish an exclusion list with thousands of specific
    # routes instead of a default. Accept it only when its public routes reach
    # both halves of a family; one half or a private-only tunnel stays fail-closed.
    $candidateIndices = @($candidates | ForEach-Object { [int]$_.InterfaceIndex } | Sort-Object -Unique)
    $publicHalves = @{}
    foreach ($route in @($Routes | Where-Object { [int]$_.InterfaceIndex -in $candidateIndices })) {
        $prefix = [string]$route.DestinationPrefix
        if (-not (Test-PublicRoutePrefix $prefix)) { continue }
        $address = [Net.IPAddress]::Parse($prefix.Split('/')[0])
        if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
            $half = if ($address.GetAddressBytes()[0] -lt 128) { 'IPv4 lower' } else { 'IPv4 upper' }
        } else {
            $half = if ($address.GetAddressBytes()[0] -lt 0x80) { 'IPv6 lower' } else { 'IPv6 upper' }
        }
        $publicHalves["$($route.InterfaceIndex)|$half"] = $true
    }
    $split = @(foreach ($index in $candidateIndices) {
        if (($publicHalves.ContainsKey("$index|IPv4 lower") -and $publicHalves.ContainsKey("$index|IPv4 upper")) -or
            ($publicHalves.ContainsKey("$index|IPv6 lower") -and $publicHalves.ContainsKey("$index|IPv6 upper"))) { $index }
    })
    $accepted = @(@($indices) + @($split) | Sort-Object -Unique)
    return @($candidates | Where-Object InterfaceIndex -in $accepted)
}

function Resolve-ApprovedVpnGuids {
    param([object[]]$Adapters, [string[]]$Requested, [switch]$Refresh)

    $resolved = @(foreach ($item in @($Requested)) {
        if ([string]::IsNullOrWhiteSpace($item)) { continue }
        $requestedGuid = [guid]::Empty
        $isGuid = [guid]::TryParse($item, [ref]$requestedGuid)
        if ($isGuid) {
            $matches = @($Adapters | Where-Object { $_.InterfaceGuid -and [guid]$_.InterfaceGuid -eq $requestedGuid })
        } else {
            $matches = @($Adapters | Where-Object Name -eq $item)
        }
        if ($matches.Count -eq 0) {
            Write-Host "VPN interface is not connected: $item"
            if ($isGuid -and $requestedGuid -ne [guid]::Empty) { $requestedGuid.ToString() }
            continue
        }
        if ($matches.Count -ne 1) { throw "The requested adapter is ambiguous; use its exact GUID: $item" }
        if (-not (Test-VpnPathAdapter -Adapter $matches[0])) {
            if ($Refresh) {
                Write-Host "VPN interface is no longer eligible: $($matches[0].Name)"
                continue
            }
            throw "Choose a virtual VPN adapter. Physical adapters and local virtual networks such as ZeroTier and Hyper-V are excluded: $item"
        }
        if ($matches[0].Status -ne 'Up') { Write-Host "VPN interface is not connected: $($matches[0].Name)" }
        ([guid]$matches[0].InterfaceGuid).ToString()
    })
    return @($resolved | Sort-Object -Unique)
}

function Find-GuardPrograms {
    param([string[]]$ExtraPrograms, [string]$UserProfile)

    $paths = @(
        # Codex Web GPT ships a private Bun runtime. A global bun.exe or node.exe
        # may run unrelated programs and must never be included automatically.
        $versions = Join-Path $UserProfile '.codex-chatgpt-web\versions'
        if (Test-Path -LiteralPath $versions -PathType Container) {
            foreach ($dir in Get-ChildItem -LiteralPath $versions -Directory) {
                $bun = Join-Path $dir.FullName 'runtime\bun.exe'
                if (Test-Path -LiteralPath $bun -PathType Leaf) { $bun }
            }
        }
        foreach ($path in $ExtraPrograms) {
            if ($path -notmatch '^[A-Za-z]:[\\/].+\.exe$' -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
                throw "Specify an existing executable by its full local path: $path"
            }
            [IO.Path]::GetFullPath($path)
        }
    )
    return @($paths | Sort-Object -Unique)
}

function Read-GuardConfig {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $config = Get-Content -LiteralPath $Path -Encoding UTF8 -Raw | ConvertFrom-Json
    $allowedKeys = @('Mode', 'VpnAdapter', 'VpnAdapters', 'Programs')
    if ($config -isnot [pscustomobject] -or
        @($config.PSObject.Properties | Where-Object Name -notin $allowedKeys).Count -ne 0) {
        throw "Invalid config in $Path. Allowed keys: Mode, VpnAdapter, VpnAdapters, Programs."
    }
    $mode = 'auto'
    $modeSpecified = $false
    if ($null -ne $config.PSObject.Properties['Mode']) {
        if ($config.Mode -isnot [string] -or $config.Mode -notin @('auto', 'adapters', 'blockall')) {
            throw "Invalid Mode in $Path. Expected auto, adapters or blockall."
        }
        $mode = $config.Mode
        $modeSpecified = $true
    }
    $adapters = @()
    if ($null -ne $config.PSObject.Properties['VpnAdapters']) {
        if ($config.VpnAdapters -isnot [array] -or
            @($config.VpnAdapters | Where-Object { $null -ne $_ -and $_ -isnot [string] }).Count -ne 0) {
            throw "Invalid VpnAdapters in $Path. Expected an array of adapter names or GUIDs."
        }
        $adapters = @($config.VpnAdapters | Where-Object { $_ })
    } elseif ($null -ne $config.PSObject.Properties['VpnAdapter']) {
        if ($null -ne $config.VpnAdapter -and $config.VpnAdapter -isnot [string]) {
            throw "Invalid VpnAdapter in $Path. Expected an adapter name or GUID."
        }
        if ($config.VpnAdapter) { $adapters = @($config.VpnAdapter) }
    }
    $programs = @()
    if ($null -ne $config.PSObject.Properties['Programs']) {
        if ($config.Programs -isnot [array] -or
            @($config.Programs | Where-Object { $null -ne $_ -and $_ -isnot [string] }).Count -ne 0) {
            throw "Invalid Programs in $Path. Expected an array of paths."
        }
        $programs = @($config.Programs | Where-Object { $_ })
    }
    return [pscustomobject]@{ Mode = $(if (-not $modeSpecified -and $adapters.Count) { 'adapters' } else { $mode }); Adapters = $adapters; Programs = $programs }
}

function Assert-GuardRuntimeItem {
    param([string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Guard runtime is a reparse point: $Path" }
    $acl = Get-Acl -LiteralPath $Path
    $sidType = [Security.Principal.SecurityIdentifier]
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($acl.GetOwner($sidType).Value -notin $trusted) { throw "Guard runtime has an untrusted owner: $Path" }
    # GenericWrite/GenericAll may also be present as generic NTFS rights.
    $writeRights = [Security.AccessControl.FileSystemRights]'Write, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $writeMask = [int]$writeRights -bor 0x50000000
    foreach ($rule in $acl.GetAccessRules($true, $true, $sidType)) {
        if ($rule.AccessControlType -eq 'Allow' -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ([int]$rule.FileSystemRights -band $writeMask) -and $rule.IdentityReference.Value -notin $trusted) {
            throw "Guard runtime can be changed without administrator permissions: $Path"
        }
    }
}

function Test-GuardRuntimePath {
    param([string]$Path)
    if (-not $Path -or -not [IO.Path]::IsPathRooted($Path)) { return $false }
    $normalized = [IO.Path]::GetFullPath($Path)
    return [IO.Path]::GetDirectoryName($normalized) -eq $RuntimeRoot -and
        [IO.Path]::GetFileName($normalized) -match '^guard-[a-f0-9]{64}$'
}

function Read-ApprovedGuardPolicy {
    param([string]$Runtime)
    if (-not (Test-GuardRuntimePath $Runtime)) { throw 'The background task requires an approved runtime in Program Files.' }
    Assert-GuardRuntimeItem $RuntimeRoot
    Assert-GuardRuntimeItem $Runtime
    foreach ($name in $RuntimeFiles + $PolicyFileName) { Assert-GuardRuntimeItem (Join-Path $Runtime $name) }
    return Read-GuardConfig (Join-Path $Runtime $PolicyFileName)
}

function Read-GuardPolicyForMigration {
    param($Task)

    if ($Task) {
        if ($Task.Settings.Enabled -eq $false -or
            -not @($Task.Triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -and $_.Enabled -ne $false }).Count) {
            return
        }
        $user = [Security.Principal.WindowsIdentity]::GetCurrent()
        # The ScheduledTasks provider can shorten Principal.UserId to a local
        # account name. The registered XML retains the canonical account SID.
        $registered = [xml](Export-ScheduledTask -TaskName $TaskName -TaskPath '\')
        $owner = [string]$registered.Task.Principals.Principal.UserId
        $action = $Task.Actions[0]
        $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $runtime = [string]$action.WorkingDirectory
        if ($owner -notin @($user.Name, $user.User.Value) -or
            $action.Execute -ne $powershell -or -not $runtime -or
            $action.Arguments.IndexOf(('-File "' + (Join-Path $runtime 'gpt_vpn_guard_watch.ps1') + '"'),
                [StringComparison]::OrdinalIgnoreCase) -lt 0) { return }
        if (Test-GuardRuntimePath $runtime) { return Read-ApprovedGuardPolicy $runtime }
    } elseif ((Test-Path -LiteralPath $ManualOnlyPath) -or (Test-Path -LiteralPath $LegacySetupLockPath)) {
        return
    }

    # Older versions did not save an approved policy. Preserve the actual
    # restrictions from WFP, including an intentional block-all setting.
    $installed = [GptVpnFilter]::ReadInstalledPolicy()
    if (-not $installed.FilterCount) { return }
    $privateBun = Join-Path $env:USERPROFILE '.codex-chatgpt-web\versions\'
    $programs = @($installed.Programs | Where-Object { -not $_.StartsWith($privateBun, [StringComparison]::OrdinalIgnoreCase) })
    $mode = if ($installed.Adapters.Count) { 'adapters' } else { 'blockall' }
    if ($mode -eq 'blockall') { Write-Host 'У старой защиты сохранилась только блокировка. Она будет перенесена без разрешения внешнего доступа.' }
    return [pscustomobject]@{ Mode = $mode; Adapters = @($installed.Adapters | ForEach-Object { $_.ToString() }); Programs = $programs }
}

function Publish-GuardRuntime {
    param([string]$Mode, [string[]]$Adapters, [string[]]$Programs)

    $files = [ordered]@{}
    foreach ($name in $RuntimeFiles) { $files[$name] = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot $name)) }
    $json = [ordered]@{ Mode = $Mode; VpnAdapters = @($Adapters | Where-Object { $_ }); Programs = @($Programs | Where-Object { $_ }) } |
        ConvertTo-Json -Compress
    $files[$PolicyFileName] = [Text.Encoding]::UTF8.GetBytes($json)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $hashes = [ordered]@{}
        foreach ($name in $files.Keys) { $hashes[$name] = [BitConverter]::ToString($sha.ComputeHash([byte[]]$files[$name])).Replace('-', '') }
        $key = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes(($hashes.Values -join '')))).Replace('-', '').ToLowerInvariant()
        [void][IO.Directory]::CreateDirectory($RuntimeRoot)
        Assert-GuardRuntimeItem $RuntimeRoot
        $runtime = Join-Path $RuntimeRoot "guard-$key"
        [void][IO.Directory]::CreateDirectory($runtime)
        Assert-GuardRuntimeItem $runtime
        foreach ($name in $files.Keys) {
            $path = Join-Path $runtime $name
            if (-not (Test-Path -LiteralPath $path)) {
                $temporary = Join-Path $runtime ([guid]::NewGuid().ToString('N') + '.tmp')
                try {
                    [IO.File]::WriteAllBytes($temporary, [byte[]]$files[$name])
                    [IO.File]::Move($temporary, $path)
                } finally {
                    if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
                }
            }
            Assert-GuardRuntimeItem $path
            if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $hashes[$name]) {
                throw "Guard runtime file does not match the approved copy: $path"
            }
        }
        return $runtime
    } finally { $sha.Dispose() }
}

function Open-GuardSetupLock {
    [void][IO.Directory]::CreateDirectory($RuntimeRoot)
    Assert-GuardRuntimeItem $RuntimeRoot
    $path = Join-Path $RuntimeRoot 'guard-operation.lock'
    if (Test-Path -LiteralPath $path) { Assert-GuardRuntimeItem $path }
    try { return [IO.File]::Open($path, 'OpenOrCreate', 'ReadWrite', 'None') }
    catch [IO.IOException] { throw "Could not lock GPT VPN setup: $($_.Exception.Message)" }
}

function Get-GuardStartup {
    return Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction SilentlyContinue
}

function Register-GuardStartup {
    param([string]$Runtime)
    $watch = Join-Path $Runtime 'gpt_vpn_guard_watch.ps1'
    $arguments = "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$watch`""
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $Runtime
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskName $TaskName -TaskPath '\' -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description 'Re-applies the VPN-only policy for ChatGPT and Codex at logon and on network changes.' -Force | Out-Null
}

function Stop-GuardStartup {
    $task = Get-GuardStartup
    if (-not $task) { return }
    Disable-ScheduledTask -InputObject $task | Out-Null
    Stop-ScheduledTask -InputObject $task
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        if ((Get-GuardStartup).State -ne 'Running') { return }
        Start-Sleep -Milliseconds 500
    }
    throw 'The previous guard task is still running.'
}

function Stop-ForeignGuardWatchers {
    param([string[]]$Keep)

    # A replaced task can leave a watcher from an older runtime running under the
    # Task Scheduler service. That watcher would keep re-applying the old policy,
    # so stop every watcher except the runtime being registered now.
    $pattern = [regex]::Escape($RuntimeRoot) + '\\guard-[a-f0-9]{64}'
    $kept = @($Keep | Where-Object { $_ } | ForEach-Object { [IO.Path]::GetFullPath($_) })
    foreach ($process in @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue)) {
        $commandLine = [string]$process.CommandLine
        if ($commandLine -notmatch ($pattern + '\\gpt_vpn_guard_watch\.ps1')) { continue }
        if ($kept -contains [regex]::Match($commandLine, $pattern).Value) { continue }
        try {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
            Write-Host "Stopped an outdated guard watcher: $($process.ProcessId)"
        } catch {
            if (Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue) {
                throw "An outdated guard watcher is still running ($($process.ProcessId)). Stop it manually or restart Windows, then enable the guard again. $($_.Exception.Message)"
            }
        }
    }
}

function Write-GuardAdapterList {
    param([object[]]$Adapters, [object[]]$Permitted)
    $permittedIds = @($Permitted | ForEach-Object { $_.InterfaceGuid })
    Write-Host 'Сетевые адаптеры Windows'
    for ($index = 0; $index -lt $Adapters.Count; $index++) {
        $adapter = $Adapters[$index]
        $reason = Get-VpnAdapterExclusion $adapter
        if ($reason) { $note = "выбор запрещён ($reason)" }
        elseif ($adapter.Status -ne 'Up') { $note = 'сейчас не подключён' }
        elseif ($adapter.InterfaceGuid -in $permittedIds) { $note = 'выбран для VPN' }
        else { $note = 'доступен для ручного выбора' }
        Write-Host ("  {0}  {1} [{2}] — {3} | ifIndex {4} | GUID {5} | {6}" -f ($index + 1),
            $adapter.Name, $adapter.InterfaceDescription, $adapter.Status, $adapter.InterfaceIndex, $adapter.InterfaceGuid, $note)
    }
}

function Select-GuidedVpnAdapters {
    param([object[]]$Adapters)

    $choices = @($Adapters | Sort-Object Name)
    Write-GuardAdapterList -Adapters $choices
    if (-not @(Get-VpnPathAdapters -Adapters $choices | Where-Object Status -eq 'Up').Count) {
        Write-Host 'Подключённый VPN не найден. Автоматический режим проверит маршруты, когда VPN появится.'
        return @()
    }
    while ($true) {
        $answer = Read-Host 'Номера VPN через запятую (Enter — автоматический выбор по маршрутам)'
        if ([string]::IsNullOrWhiteSpace($answer)) { return @() }
        $picked = @()
        $valid = $true
        foreach ($token in ($answer -split ',')) {
            $number = 0
            if (-not [int]::TryParse($token.Trim(), [ref]$number) -or $number -lt 1 -or $number -gt $choices.Count) {
                $valid = $false
                break
            }
            $adapter = $choices[$number - 1]
            $reason = Get-VpnAdapterExclusion $adapter
            if ($reason -or $adapter.Status -ne 'Up') {
                if (-not $reason) { $reason = 'интерфейс сейчас не подключён' }
                Write-Host "Адаптер $($adapter.Name) недоступен для выбора ($reason)."
                $valid = $false
                break
            }
            $picked += $adapter
        }
        if ($valid) { return @($picked | Sort-Object Name -Unique) }
        Write-Host 'Введите номера адаптеров, доступных для выбора.'
    }
}

if ($Help) {
    Get-Help -Name $PSCommandPath -Detailed
    exit 0
}

$setupLock = $null
try {
    $selection = $BlockAll -or $Guided -or $Auto -or $VpnAdapter -or $Program -or $ChooseVpn -or $NoStartup
    if ((($Status -or $Remove -or $Reapply -or $Migrate) -and ($Plan -or $selection)) -or
        @(@($Status, $Remove, $Reapply, $Migrate) | Where-Object { $_ }).Count -gt 1) {
        throw 'Incompatible guard operations.'
    }
    if (($ChooseVpn -and -not $Guided) -or ($Guided -and $BlockAll)) { throw 'Incompatible VPN selection modes.' }

    $admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($Migrate -and (-not $Packaged -or -not $admin)) { throw 'Guard migration must run from the elevated launcher.' }
    if (-not $Plan -and -not $Reapply -and -not $admin) {
        if ($PSBoundParameters.ContainsKey('Program') -or $VpnAdapter) {
            throw 'Open PowerShell as Administrator when passing -VpnAdapter or -Program, or set them in gpt_vpn_guard.local.json.'
        }
        $argsForAdmin = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        if ($Packaged) { $argsForAdmin += ' -Packaged' }
        if ($Guided) { $argsForAdmin += ' -Guided' }
        if ($ChooseVpn) { $argsForAdmin += ' -ChooseVpn' }
        if ($Remove) { $argsForAdmin += ' -Remove' }
        if ($Status) { $argsForAdmin += ' -Status' }
        if ($BlockAll) { $argsForAdmin += ' -BlockAll' }
        if ($Auto) { $argsForAdmin += ' -Auto' }
        if ($NoStartup) { $argsForAdmin += ' -NoStartup' }
        $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList $argsForAdmin -Verb RunAs -PassThru -Wait
        exit $process.ExitCode
    }
    if ($Reapply -and -not $admin) { throw 'The background task must run with Administrator permissions.' }

    $oldTask = if (-not $Reapply) { Get-GuardStartup }
    $oldRuntime = if ($oldTask) { [string]$oldTask.Actions[0].WorkingDirectory }
    if ($Status -or $Remove) {
        if (-not ('GptVpnFilter' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'gpt_vpn_filter.cs') }
        if ($Remove) {
            $setupLock = Open-GuardSetupLock
            $oldTask = Get-GuardStartup
            if ($oldTask) {
                Stop-GuardStartup
                Unregister-ScheduledTask -InputObject $oldTask -Confirm:$false | Out-Null
            }
            Write-Host "Removed GPT VPN filters: $([GptVpnFilter]::Remove())"
            if (Test-Path -LiteralPath $ManualOnlyPath) { Remove-Item -LiteralPath $ManualOnlyPath -Force }
            exit 0
        }

        $count = [GptVpnFilter]::Count()
        Write-Host "Installed GPT VPN filters: $count"
        if ($oldTask) {
            Write-Host "Задача: $TaskName ($($oldTask.State))"
            if (Test-GuardRuntimePath $oldRuntime) {
                $approved = Read-ApprovedGuardPolicy $oldRuntime
                Write-Host "Mode: $($approved.Mode)"
                Write-Host "Журнал: $(Join-Path $oldRuntime 'guard-watch.log')"
            } else { Write-Warning 'Задача использует старую папку. Повторно включите защиту из текущей версии.' }
        } else { Write-Host 'Автоприменение при входе выключено.' }
        Write-GuardAdapterList -Adapters @(Get-NetAdapter -IncludeHidden | Sort-Object Name)
        exit 0
    }

    if ($Migrate) {
        $setupLock = Open-GuardSetupLock
        if (-not ('GptVpnFilter' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'gpt_vpn_filter.cs') }
        $oldTask = Get-GuardStartup
        $config = Read-GuardPolicyForMigration $oldTask
        if (-not $config) { exit 3 }
        $oldRuntime = if ($oldTask) { [string]$oldTask.Actions[0].WorkingDirectory }
    } elseif ($Reapply) { $config = Read-ApprovedGuardPolicy $PSScriptRoot } else {
        $draft = Read-GuardConfig -Path $ConfigPath
        $config = if ($draft) { $draft } elseif (Test-GuardRuntimePath $oldRuntime) { Read-ApprovedGuardPolicy $oldRuntime }
    }
    $mode = if ($config) { $config.Mode } else { 'auto' }
    $savedAdapters = if ($config) { @($config.Adapters) } else { @() }
    $savedPrograms = if ($config) { @($config.Programs) } else { @() }

    if ($BlockAll) { $mode = 'blockall'; $savedAdapters = @() }
    elseif ($VpnAdapter) { $mode = 'adapters'; $savedAdapters = @($VpnAdapter) }
    elseif ($Auto) { $mode = 'auto'; $savedAdapters = @() }

    if (-not $PSBoundParameters.ContainsKey('Program') -and $savedPrograms.Count) { $Program = @($savedPrograms) }

    $allAdapters = @()
    if ($Plan -or $mode -ne 'blockall' -or ($Guided -and $ChooseVpn)) { $allAdapters = @(Get-NetAdapter -IncludeHidden) }
    if ($Guided -and $ChooseVpn -and -not $Plan) {
        $picked = @(Select-GuidedVpnAdapters -Adapters $allAdapters)
        if ($picked.Count) { $mode = 'adapters'; $savedAdapters = @($picked | ForEach-Object { $_.InterfaceGuid.ToString() }) }
        else { $mode = 'auto'; $savedAdapters = @() }
    }

    $approvedGuids = @()
    $adapters = @(switch ($mode) {
        'blockall' { }
        'adapters' {
            $approvedGuids = @(Resolve-ApprovedVpnGuids -Adapters $allAdapters -Requested $savedAdapters -Refresh:($Reapply -or $Migrate))
            Get-VpnPathAdapters -Adapters $allAdapters | Where-Object {
                $_.Status -eq 'Up' -and ([guid]$_.InterfaceGuid).ToString() -in $approvedGuids
            }
        }
        default { Get-AutomaticVpnAdapters -Adapters $allAdapters -Routes @(Get-NetRoute -PolicyStore ActiveStore) }
    })
    $extra = @(Find-GuardPrograms -ExtraPrograms $Program -UserProfile $env:USERPROFILE)
    if ($adapters.Count) {
        foreach ($adapter in $adapters) { Write-Host "VPN interface: $($adapter.Name) ($($adapter.InterfaceGuid))" }
    } else {
        Write-Host 'No VPN exception: all external connections from the protected applications will be blocked.'
    }
    Write-Host "Mode: $mode"
    Write-Host "Executable names: $($ExecutableNames -join ', ')"
    Write-Host "OpenAI packages: $($PackageFamilies -join ', ')"
    foreach ($path in $extra) { Write-Host "Additional executable: $path" }
    if ($Plan -or (-not $Reapply -and -not $ChooseVpn -and $allAdapters.Count)) {
        Write-GuardAdapterList -Adapters @($allAdapters | Sort-Object Name) -Permitted $adapters
    }
    if ($Plan) { exit 0 }

    if (-not ('GptVpnFilter' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'gpt_vpn_filter.cs') }
    if (-not $Reapply) {
        if (-not $setupLock) {
            $setupLock = Open-GuardSetupLock
            $oldTask = Get-GuardStartup
        }
        if (-not $NoStartup) {
            $runtime = Publish-GuardRuntime -Mode $mode -Adapters $approvedGuids -Programs @($Program)
        }
        Stop-GuardStartup
        $keepWatchers = @($PSScriptRoot)
        if (-not $NoStartup) { $keepWatchers += $runtime }
        Stop-ForeignGuardWatchers -Keep $keepWatchers
        if ($NoStartup) {
            if (-not (Test-Path -LiteralPath $ManualOnlyPath)) {
                New-Item -Path $ManualOnlyPath -ItemType File | Out-Null
            }
            if ($oldTask) { Unregister-ScheduledTask -InputObject $oldTask -Confirm:$false | Out-Null }
        } else {
            try { Register-GuardStartup -Runtime $runtime }
            catch {
                if ($Migrate -and (Test-GuardRuntimePath $oldRuntime)) {
                    $previous = Get-GuardStartup
                    if ($previous -and $previous.Actions[0].WorkingDirectory -eq $oldRuntime) {
                        Enable-ScheduledTask -InputObject $previous | Out-Null
                        Start-ScheduledTask -InputObject $previous
                    }
                }
                throw
            }
            if (Test-Path -LiteralPath $ManualOnlyPath) { Remove-Item -LiteralPath $ManualOnlyPath -Force }
        }
    }

    $guids = @($adapters | ForEach-Object { [guid]$_.InterfaceGuid })
    try {
        $count = [GptVpnFilter]::Apply([guid[]]$guids, $ExecutableNames, $extra, $PackageFamilies)
        Write-Host "Installed GPT VPN filters: $count (blocking rules persist after restart)."
    } finally {
        if (-not $Reapply -and -not $NoStartup) {
            Start-ScheduledTask -TaskName $TaskName -TaskPath '\'
        }
    }
    if (-not $Reapply -and -not $NoStartup) { Write-Host "Автоприменение при входе включено. Журнал: $(Join-Path $runtime 'guard-watch.log')" }
    exit 0
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
} finally {
    if ($null -ne $setupLock) { $setupLock.Dispose() }
}
