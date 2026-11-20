# Exercise the watch loop in memory without scheduling a task or changing WFP.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'gpt_vpn_guard_watch.ps1'
$tokens = $null
$errors = $null
$watcher = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }
$signatureFunction = $watcher.EndBlock.Statements | Where-Object {
    $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $_.Name -eq 'Get-NetworkSignature'
}
. ([scriptblock]::Create($signatureFunction.Extent.Text))
$loop = $watcher.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.WhileStatementAst] }

$script:polls = 0
$script:attempts = @()
$script:metric = 8
$script:bfe = 10
function Get-NetAdapter {
    param([switch]$IncludeHidden)
    [pscustomobject]@{ ifIndex = 21; Name = 'Tunnel'; Status = 'Up'; InterfaceGuid = [guid]::Empty;
        HardwareInterface = $false; InterfaceDescription = 'TAP'; InterfaceType = 53 }
}
function Get-NetRoute {
    param([string]$PolicyStore)
    if ($PolicyStore -ne 'ActiveStore') { throw 'Watcher must inspect active routes' }
    [pscustomobject]@{ InterfaceIndex = 21; DestinationPrefix = '0.0.0.0/0'; RouteMetric = $script:metric; InterfaceMetric = 3 }
}
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter)
    [pscustomobject]@{ ProcessId = $script:bfe; State = 'Running' }
}
function Write-WatchLog([string]$Message) { }
function Invoke-GuardApply {
    $script:attempts += $script:polls
    $code = if ($script:attempts.Count -eq 1) { 1 } else { 0 }
    return [pscustomobject]@{ Code = $code; Output = 'simulated' }
}
function Start-Sleep([int]$Seconds) {
    if ($Seconds -ne 5) { throw 'Unexpected watcher retry interval' }
    $script:polls++
    if ($script:polls -eq 3) { $script:metric++ }
    if ($script:polls -eq 4) { $script:bfe++ }
    if ($script:polls -eq 5) { throw 'end of watcher fixture' }
}

$lastSignature = ''
$nextRefresh = [datetime]::MinValue
$Once = $false
try { & ([scriptblock]::Create($loop.Extent.Text)) }
catch { if ($_.Exception.Message -ne 'end of watcher fixture') { throw } }
if (($script:attempts -join ',') -ne '0,1,3,4') {
    throw "Wanted immediate retry, no unnecessary apply, refresh on a route and BFE change. Saw: $script:attempts"
}
Write-Host 'PASS: watcher retries a failed apply and responds to route and filtering-service changes'
