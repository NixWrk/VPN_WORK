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
    $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Sort-Object ifIndex)
    $parts = @($adapters | ForEach-Object {
        '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $_.ifIndex, $_.Name, $_.Status, $_.InterfaceGuid,
            $_.HardwareInterface, $_.InterfaceDescription, $_.InterfaceType
    })
    # Only the winning interfaces matter. Raw metrics of a physical adapter can
    # flap without changing the VPN choice, and applying WFP filters every few
    # seconds is expensive.
    $prefixes = @('0.0.0.0/0', '0.0.0.0/1', '128.0.0.0/1', '::/0', '::/1', '8000::/1')
    $routes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
    $defaultRoutes = @($routes | Where-Object DestinationPrefix -in $prefixes)
    $selected = @(foreach ($prefix in $prefixes) {
        $matching = @($defaultRoutes | Where-Object DestinationPrefix -eq $prefix)
        if (-not $matching.Count) { continue }
        $cost = ($matching | ForEach-Object { [long]$_.RouteMetric + [long]$_.InterfaceMetric } |
            Measure-Object -Minimum).Minimum
        $owners = @($matching | Where-Object { [long]$_.RouteMetric + [long]$_.InterfaceMetric -eq $cost } |
            Select-Object -ExpandProperty InterfaceIndex -Unique | Sort-Object)
        '{0}|{1}' -f $prefix, ($owners -join ',')
    })
    # Split routes may arrive after the adapter is already Up. Route identity
    # matters here, not metric changes or changes on physical interfaces.
    $tunnelIndices = @($adapters | Where-Object {
        $_.Status -eq 'Up' -and $_.HardwareInterface -eq $false -and $_.InterfaceType -in @(23, 53, 131)
    } | ForEach-Object { $_.ifIndex })
    $splitRoutes = @($routes | Where-Object {
        $_.InterfaceIndex -in $tunnelIndices -and $_.DestinationPrefix -notin $prefixes
    } | ForEach-Object { '{0}|{1}' -f $_.InterfaceIndex, $_.DestinationPrefix } | Sort-Object -Unique)
    return ($parts + $selected + $splitRoutes) -join "`n"
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
