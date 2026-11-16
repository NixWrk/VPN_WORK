<#
.SYNOPSIS
Protects ChatGPT, Codex and explicitly selected Windows executables with a VPN-only network policy.
.PARAMETER VpnAdapter
Exact Windows adapter name or GUID. Must be a virtual VPN interface. With no explicit selection,
the installer offers a list of connected virtual interfaces. No selection means block all external traffic.
.PARAMETER Program
Additional absolute .exe path(s), e.g. a browser dedicated to ChatGPT.
The entire executable is protected, including its other profiles and tabs.
.PARAMETER BlockAll
Install the policy without any VPN exception. Local loopback still works.
.PARAMETER Plan
Show selected adapter or available choices and protected applications without changing WFP or requesting elevation.
.PARAMETER Status
Show the number of installed WFP filters. Requires an Administrator terminal.
.PARAMETER Remove
Remove only this script's protection. Requires Administrator permissions.
#>
[CmdletBinding()]
param(
    [string]$VpnAdapter,
    [string[]]$Program,
    [switch]$BlockAll,
    [switch]$Plan,
    [switch]$Status,
    [switch]$Remove,
    [Parameter(DontShow = $true)][switch]$Packaged,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$ExecutableNames = @('ChatGPT.exe', 'Codex.exe', 'Codex Web GPT.exe',
    'codex-code-mode-host.exe', 'codex-computer-use-swift.exe',
    'codex-windows-sandbox.exe', 'codex-windows-sandbox-service.exe')
$PackageFamilies = @('OpenAI.Codex_2p2nqsd0c76g0', 'OpenAI.ChatGPT-Desktop_2p2nqsd0c76g0')
$configDirectory = if ($Packaged) { Join-Path $env:LOCALAPPDATA 'VPN_WORK' } else { $PSScriptRoot }
$ConfigPath = Join-Path $configDirectory 'gpt_vpn_guard.local.json'

function Get-VpnAdapterChoices {
    param([object[]]$Adapters)
    $Adapters | Where-Object {
        $_.HardwareInterface -eq $false -and $_.InterfaceGuid -and $_.Status -eq 'Up' -and
        $_.InterfaceDescription -notmatch 'ZeroTier|Hyper-V|Loopback|Bluetooth|Wi-Fi Direct' -and
        $_.InterfaceDescription -notmatch '^WAN Miniport \((IP|IPv6|Network Monitor|PPPOE)\)$'
    } | Sort-Object Name
}

function Select-VpnAdapter {
    param([object[]]$Adapters, [string]$Requested, [switch]$Prompt)

    if ($Requested) {
        $requestedGuid = [guid]::Empty
        if ([guid]::TryParse($Requested, [ref]$requestedGuid)) {
            $matches = @($Adapters | Where-Object { $_.InterfaceGuid -and [guid]$_.InterfaceGuid -eq $requestedGuid })
        } else {
            $matches = @($Adapters | Where-Object Name -eq $Requested)
        }
        if ($matches.Count -eq 0) { return }
        if ($matches.Count -ne 1) { throw 'The requested adapter is ambiguous; use its exact GUID.' }
        if ($matches[0].Status -ne 'Up') { return }
        if (-not (Get-VpnAdapterChoices -Adapters $matches)) {
            throw 'Choose a connected virtual VPN adapter; LAN, ZeroTier and host-only adapters are not VPN targets.'
        }
        return $matches[0]
    }

    $choices = @(Get-VpnAdapterChoices -Adapters $Adapters)
    if ($choices.Count -eq 0) { return }
    Write-Host 'Connected virtual interfaces (choose only the one belonging to your VPN):'
    for ($index = 0; $index -lt $choices.Count; $index++) {
        $item = $choices[$index]
        Write-Host "  $($index + 1). $($item.Name) [$($item.InterfaceDescription)] ($($item.InterfaceGuid))"
    }
    if (-not $Prompt) { return }
    $answer = Read-Host 'VPN interface number (Enter to block all external connections)'
    if (-not $answer) { return }
    $number = 0
    if (-not [int]::TryParse($answer, [ref]$number) -or $number -lt 1 -or $number -gt $choices.Count) {
        throw 'Invalid adapter number; run setup again or use -BlockAll.'
    }
    return $choices[$number - 1]
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

if ($Help) {
    Get-Help -Name $PSCommandPath -Detailed
    exit 0
}

try {
    if (($Status -or $Remove) -and ($Plan -or $BlockAll -or $VpnAdapter -or $Program -or ($Status -and $Remove))) {
        throw 'Use -Status or -Remove on its own.'
    }

    $admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $Plan -and -not $admin) {
        if ($PSBoundParameters.ContainsKey('Program') -or $VpnAdapter) {
            throw 'Open PowerShell as Administrator when passing -VpnAdapter or -Program, or set them in gpt_vpn_guard.local.json.'
        }
        $argsForAdmin = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
        if ($Packaged) { $argsForAdmin += ' -Packaged' }
        if ($Remove) { $argsForAdmin += ' -Remove' }
        if ($Status) { $argsForAdmin += ' -Status' }
        if ($BlockAll) { $argsForAdmin += ' -BlockAll' }
        $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
            -ArgumentList $argsForAdmin -Verb RunAs -PassThru -Wait
        exit $process.ExitCode
    }

    if (-not $Status -and -not $Remove) {
        if (Test-Path -LiteralPath $ConfigPath) {
            $config = Get-Content -LiteralPath $ConfigPath -Encoding UTF8 -Raw | ConvertFrom-Json
            if ($config -isnot [pscustomobject] -or
                @($config.PSObject.Properties | Where-Object Name -notin @('VpnAdapter', 'Programs')).Count -ne 0 -or
                ($null -ne $config.VpnAdapter -and $config.VpnAdapter -isnot [string]) -or
                ($null -ne $config.Programs -and $config.Programs -isnot [array]) -or
                @($config.Programs | Where-Object { $null -ne $_ -and $_ -isnot [string] }).Count -ne 0) {
                throw "Invalid config in $ConfigPath. Expected VpnAdapter (string) and Programs (array of paths)."
            }
            if (-not $PSBoundParameters.ContainsKey('VpnAdapter')) { $VpnAdapter = $config.VpnAdapter }
            if (-not $PSBoundParameters.ContainsKey('Program') -and $null -ne $config.Programs) { $Program = @($config.Programs) }
        }
        $extra = @(Find-GuardPrograms -ExtraPrograms $Program -UserProfile $env:USERPROFILE)
        $adapter = $null
        if (-not $BlockAll) {
            $adapter = Select-VpnAdapter -Adapters @(Get-NetAdapter -IncludeHidden) -Requested $VpnAdapter -Prompt:(-not $Plan)
        }
        $adapterGuid = [guid]::Empty
        if ($adapter) {
            $adapterGuid = [guid]$adapter.InterfaceGuid
            Write-Host "VPN interface: $($adapter.Name) ($adapterGuid)"
        } else {
            Write-Host 'No VPN exception: all external connections from the protected applications will be blocked.'
        }
        Write-Host "Executable names: $($ExecutableNames -join ', ')"
        Write-Host "OpenAI packages: $($PackageFamilies -join ', ')"
        foreach ($path in $extra) { Write-Host "Additional executable: $path" }
        if ($Plan) { exit 0 }
    }

    Add-Type -Path (Join-Path $PSScriptRoot 'gpt_vpn_filter.cs')
    if ($Status) {
        $count = [GptVpnFilter]::Count()
        Write-Host "Installed GPT VPN filters: $count"
        if ($count -eq 0) { exit 1 }
    } elseif ($Remove) {
        Write-Host "Removed GPT VPN filters: $([GptVpnFilter]::Remove())"
    } else {
        $count = [GptVpnFilter]::Apply($adapterGuid, $ExecutableNames, $extra, $PackageFamilies)
        Write-Host "Installed GPT VPN filters: $count (blocking rules persist after restart)."
    }
    exit 0
} catch {
    Write-Host "ERROR: $($_.Exception.Message)"
    exit 1
}
