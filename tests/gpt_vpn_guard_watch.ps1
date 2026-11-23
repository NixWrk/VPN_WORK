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
$guardPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'gpt_vpn_guard.ps1'
$guard = [System.Management.Automation.Language.Parser]::ParseFile($guardPath, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors -join "`n") }
$routeFunctions = @('Get-VpnAdapterExclusion','Test-VpnPathAdapter','Get-VpnPathAdapters','Get-PublicRouteGroup','Get-AutomaticVpnAdapters')
foreach ($definition in $guard.EndBlock.Statements | Where-Object Name -in $routeFunctions) {
    . ([scriptblock]::Create($definition.Extent.Text))
}

function New-TestAdapter([int]$Index, [string]$Name, [int]$Type, [bool]$Hardware, [string]$Status) {
    [pscustomobject]@{ Name = $Name; InterfaceDescription = $Name; InterfaceGuid = [guid]::NewGuid();
        Status = $Status; ifIndex = $Index; InterfaceIndex = $Index; HardwareInterface = $Hardware; InterfaceType = $Type }
}
function New-TestRoute([int]$Index, [string]$Prefix, [int]$Metric = 8) {
    [pscustomobject]@{ InterfaceIndex = $Index; DestinationPrefix = $Prefix; RouteMetric = $Metric; InterfaceMetric = 3 }
}
$script:lan = New-TestAdapter 9 'Wi-Fi' 71 $true 'Up'
$script:oldVpn = New-TestAdapter 21 'OpenVPN' 53 $false 'Up'
$script:newVpn = New-TestAdapter 22 'WireGuard' 53 $false 'Down'
$script:lanDefault = New-TestRoute 9 '0.0.0.0/0' 30
$script:routes = @($script:lanDefault, (New-TestRoute 21 '0.0.0.0/0'))
$script:polls = 0
$script:attempts = @()
$script:permitted = @()
function Get-NetAdapter {
    [CmdletBinding()]
    param([switch]$IncludeHidden)
    return @($script:lan, $script:oldVpn, $script:newVpn)
}
function Get-NetRoute {
    [CmdletBinding()]
    param([string]$PolicyStore)
    if ($PolicyStore -ne 'ActiveStore') { throw 'Watcher must inspect active routes' }
    return $script:routes
}
function Write-WatchLog([string]$Message) { }
function Invoke-GuardApply {
    $script:attempts += $script:polls
    $code = if ($script:attempts.Count -eq 1) { 1 } else { 0 }
    if ($code -eq 0) {
        $allowed = @(Get-AutomaticVpnAdapters -Adapters @(Get-NetAdapter) -Routes $script:routes | ForEach-Object Name)
        $script:permitted += $(if ($allowed.Count) { $allowed -join ',' } else { 'blocked' })
    }
    return [pscustomobject]@{ Code = $code; Output = 'simulated' }
}
function Start-Sleep([int]$Seconds) {
    if ($Seconds -ne 5) { throw 'Unexpected watcher retry interval' }
    $script:polls++
    switch ($script:polls) {
        2 { $script:lanDefault.RouteMetric++ }
        3 { $script:oldVpn.Status = 'Down'; $script:newVpn.Status = 'Up'; $script:routes = @($script:lanDefault) }
        4 { $script:routes += New-TestRoute 22 '45.140.176.0/22' }
        5 { $script:routes[1].RouteMetric++ }
        6 { $script:routes += New-TestRoute 22 '185.220.100.0/22' }
        7 { $script:routes += New-TestRoute 9 '77.88.44.55/32' }
        8 { $script:routes = @($script:routes | Where-Object DestinationPrefix -ne '185.220.100.0/22') }
        9 { throw 'end of watcher fixture' }
    }
}

$lastSignature = ''
$nextRefresh = [datetime]::MinValue
$Once = $false
try { & ([scriptblock]::Create($loop.Extent.Text)) }
catch { if ($_.Exception.Message -ne 'end of watcher fixture') { throw } }
if (($script:attempts -join ',') -ne '0,1,3,4,6,8' -or
    ($script:permitted -join ',') -ne 'OpenVPN,blocked,blocked,WireGuard,blocked') {
    throw "Unexpected recovery sequence. Polls $script:attempts, permissions $script:permitted"
}

$stable = Get-NetworkSignature
$script:lanDefault.RouteMetric = 99
if ((Get-NetworkSignature) -ne $stable) { throw 'A metric-only change must not trigger an apply' }
$script:routes += New-TestRoute 22 '0.0.0.0/0' 1
if ((Get-NetworkSignature) -eq $stable) { throw 'A default-route owner change must trigger an apply' }
Write-Host 'PASS: watcher retries failures, stays blocked during VPN handoff, and follows delayed split routes without reacting to metric flaps'
