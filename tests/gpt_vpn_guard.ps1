# Tests the real -Plan entry point with synthetic adapters and no WFP writes.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'gpt_vpn_guard.ps1'
$casePath = Join-Path $PSScriptRoot ('gpt-guard-' + [guid]::NewGuid().ToString('N'))
$absolute = [IO.Path]::GetFullPath($casePath)
if (-not $absolute.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary path escaped tests directory'
}
try {
    New-Item -ItemType Directory -Path $absolute | Out-Null
    $copy = Join-Path $absolute 'gpt_vpn_guard.ps1'
    Copy-Item -LiteralPath $source -Destination $copy
    $runner = Join-Path $absolute 'plan.ps1'
    @'
param([string]$Scenario)
$ErrorActionPreference = 'Stop'
$env:USERPROFILE = $PSScriptRoot
function Get-NetAdapter {
    param([switch]$IncludeHidden)
    [pscustomobject]@{Name='Wi-Fi'; InterfaceDescription='Wi-Fi'; Status='Up'; HardwareInterface=$true; InterfaceGuid=[guid]::NewGuid()}
    [pscustomobject]@{Name='ZeroTier'; InterfaceDescription='ZeroTier Virtual Port'; Status='Up'; HardwareInterface=$false; InterfaceGuid=[guid]::NewGuid()}
    [pscustomobject]@{Name='Other VPN'; InterfaceDescription='TAP-Windows'; Status='Up'; HardwareInterface=$false; InterfaceGuid=[guid]::NewGuid()}
    $status = if ($Scenario -eq 'Disconnected') { 'Disconnected' } else { 'Up' }
    [pscustomobject]@{Name='Office tunnel'; InterfaceDescription='WireGuard Tunnel'; Status=$status; HardwareInterface=$false; InterfaceGuid='3be596aa-8a8e-4839-9500-2961a25e179c'}
}
function Start-Process { throw 'Plan tried to elevate' }
function Add-Type { throw 'Plan tried to load the WFP installer' }
function Read-Host { throw 'Plan tried to prompt' }
$guard = Join-Path $PSScriptRoot 'gpt_vpn_guard.ps1'
if ($Scenario -eq 'Physical') { & $guard -Plan -VpnAdapter 'Wi-Fi' }
elseif ($Scenario -eq 'Overlay') { & $guard -Plan -VpnAdapter 'ZeroTier' }
elseif ($Scenario -eq 'Missing') { & $guard -Plan -VpnAdapter 'Missing VPN' }
elseif ($Scenario -eq 'Disconnected') { & $guard -Plan -VpnAdapter 'Office tunnel' }
elseif ($Scenario -eq 'Guid') { & $guard -Plan -VpnAdapter '3be596aa-8a8e-4839-9500-2961a25e179c' }
elseif ($Scenario -eq 'BlockAll') { & $guard -Plan -BlockAll }
else { & $guard -Plan }
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath $runner -Encoding UTF8
    $private = Join-Path $absolute '.codex-chatgpt-web\versions\9.0\runtime'
    New-Item -ItemType Directory -Path $private -Force | Out-Null
    New-Item -ItemType File -Path (Join-Path $private 'bun.exe') | Out-Null
    $browser = Join-Path $absolute 'Browser With Spaces.exe'
    New-Item -ItemType File -Path $browser | Out-Null

    foreach ($scenario in @('Unselected', 'Guid', 'Disconnected', 'Missing', 'BlockAll', 'Physical', 'Overlay')) {
        $output = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner $scenario) -join "`n"
        $code = $LASTEXITCODE
        if ($scenario -in @('Physical', 'Overlay')) {
            if ($code -ne 1 -or $output -notmatch 'LAN, ZeroTier') { throw "Unsafe adapter accepted: $scenario ($output)" }
        } elseif ($scenario -eq 'Guid') {
            if ($code -ne 0 -or $output -notmatch 'VPN interface: Office tunnel' -or $output -notmatch 'runtime\\bun.exe') {
                throw "Wrong GUID selection or missing private runtime: $output"
            }
        } elseif ($code -ne 0 -or $output -notmatch 'No VPN exception' -or $output -match 'VPN interface:') {
            throw "Scenario $scenario did not fail closed: $output"
        } elseif ($scenario -eq 'Unselected' -and ($output -notmatch 'Office tunnel' -or $output -notmatch 'Other VPN' -or
            $output -match 'ZeroTier|Wi-Fi')) {
            throw "Wrong generic tunnel choices: $output"
        }
    }

    $config = Join-Path $absolute 'gpt_vpn_guard.local.json'
    @{VpnAdapter='Other VPN'; Programs=@($browser)} | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding UTF8
    $output = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner Configured) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $output -notmatch 'VPN interface: Other VPN' -or $output -notlike "*$browser*") {
        throw "Explicit adapter or browser with spaces not honored: $output"
    }
    @{Programs=@('C:\missing\browser.exe')} | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding UTF8
    $output = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner Configured) -join "`n"
    if ($LASTEXITCODE -ne 1 -or $output -notmatch 'existing executable') { throw "Invalid executable accepted: $output" }
    Write-Host 'PASS: guard plan, fail-closed adapter selection, private runtime, explicit browser, and no elevation or WFP changes'
} finally {
    if (Test-Path -LiteralPath $absolute) { Remove-Item -LiteralPath $absolute -Recurse -Force }
}
