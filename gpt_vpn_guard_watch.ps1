# Keeps the GPT VPN policy in sync with the current network.
# Interface permits cannot be persisted safely: a saved LUID may belong to another
# adapter after a restart. The deny policy stays persistent, and this task re-creates
# the permits at logon and whenever an adapter appears, disappears or changes.
[CmdletBinding()]
param([switch]$Once)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'VPN_WORK'
if ([IO.Path]::GetDirectoryName($PSScriptRoot) -ne $root -or
    [IO.Path]::GetFileName($PSScriptRoot) -notmatch '^guard-[a-f0-9]{64}$') {
    throw 'The guard watcher must run from the approved runtime in Program Files.'
}
$guard = Join-Path $PSScriptRoot 'gpt_vpn_guard.ps1'
if (-not (Test-Path -LiteralPath $guard -PathType Leaf)) { exit 1 }

$logPath = Join-Path $PSScriptRoot 'guard-watch.log'

function Write-WatchLog {
    param([string]$Message)
    try {
        if ((Test-Path -LiteralPath $logPath) -and (Get-Item -LiteralPath $logPath).Length -gt 1MB) {
            Move-Item -LiteralPath $logPath -Destination ($logPath + '.1') -Force
        }
        Add-Content -LiteralPath $logPath -Encoding UTF8 -Value ('{0:o} {1}' -f (Get-Date), $Message)
    } catch { }
}

function Get-NetworkSignature {
    $parts = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object ifIndex | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $_.ifIndex, $_.Name, $_.Status, $_.InterfaceGuid,
            $_.HardwareInterface, $_.InterfaceDescription, $_.InterfaceType
    })
    $prefixes = @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1', '::/0', '::/1', '8000::/1')
    $routes = @(Get-NetRoute -PolicyStore ActiveStore | Where-Object DestinationPrefix -in $prefixes | ForEach-Object {
        '{0}|{1}|{2}|{3}' -f $_.InterfaceIndex, $_.DestinationPrefix, $_.RouteMetric, $_.InterfaceMetric
    } | Sort-Object)
    $bfe = Get-CimInstance Win32_Service -Filter "Name='BFE'"
    return (($parts + $routes) -join "`n") + "|bfe=$($bfe.ProcessId):$($bfe.State)"
}

function Invoke-GuardApply {
    # Call the script in this process so stopping the task also stops any apply.
    $output = & $guard -Reapply *>&1
    return [pscustomobject]@{ Code = $LASTEXITCODE; Output = (@($output) -join ' ') }
}

Write-WatchLog 'watcher started'
$lastSignature = ''
$nextRefresh = [datetime]::MinValue

while ($true) {
    $exitCode = 1
    try {
        $signature = Get-NetworkSignature
        $now = Get-Date
        if ($signature -ne $lastSignature -or $now -ge $nextRefresh) {
            $result = Invoke-GuardApply
            $exitCode = $result.Code
            if ($exitCode -eq 0) {
                $lastSignature = $signature
                $nextRefresh = $now.AddMinutes(10)
            }
            Write-WatchLog ("apply exit=$($result.Code) " + $result.Output)
        }
    } catch {
        Write-WatchLog ('error: ' + $_.Exception.Message)
    }
    if ($Once) { exit $exitCode }
    Start-Sleep -Seconds 5
}
