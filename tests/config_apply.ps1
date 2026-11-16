# Run the real apply flow against an in-memory route table, never Windows networking.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'split_tunnel.ps1'
$text = [IO.File]::ReadAllText($source)
$mainIndex = $text.IndexOf('# ---- main ----')
if ($mainIndex -lt 0) { throw 'Main entry point missing' }
$prefix = $text.Substring(0, $mainIndex)
$main = $text.Substring($mainIndex)
$casePath = Join-Path $PSScriptRoot ('apply-' + [guid]::NewGuid().ToString('N'))
$mocks = @'
$ErrorActionPreference = 'Stop'
$StateFile = Join-Path $PSScriptRoot 'state.json'
$script:phase = [int][IO.File]::ReadAllText((Join-Path $PSScriptRoot 'phase.txt'))
$script:routes = @{}
foreach ($record in @((Read-ManagedState).Routes)) {
    if ($record.Prefix) { $script:routes[$record.Prefix] = $record }
}
function Write-Host { param($Object) }
function Start-Transcript { [CmdletBinding()] param($Path, [switch]$Force) }
function Test-IsAdmin { return $true }
function Find-RealGateway { [pscustomobject]@{ Gateway = '192.168.1.1'; IfIndex = 21; Desc = 'test LAN' } }
function Find-ElementDomains { return @('matrix.work.example') }
function Find-ZoteroWebDavDomains { return @() }
function Find-YouGileShardDomains { return @() }
function Find-Bitrix24DesktopDomains { return @() }
function Find-NextcloudDomain { return $null }
function Find-CachedDomainsForSuffixes {
    param($Suffixes)
    if ('.publisher.example' -in $Suffixes) { return @('cdn.publisher.example') }
    return @()
}
function Clear-DnsClientCache { [CmdletBinding()] param() }
function Get-LanDnsServers { param($Gateway); return @('8.8.8.8') }
function Test-DnsDirectViaLan { param($Server, $Gateway); return $true }
function Test-DnsCandidate { param($Server); return $true }
function Test-DnsViaNrpt { param($Server); return $true }
function Test-DnsServer { param($Server, [switch]$TcpOnly); return $true }
function Get-NetRoute {
    [CmdletBinding()] param($AddressFamily, $PolicyStore, $InterfaceIndex, $DestinationPrefix)
    if ($DestinationPrefix -eq '0.0.0.0/0') {
        return [pscustomobject]@{ DestinationPrefix = '0.0.0.0/0'; InterfaceIndex = 21; NextHop = '192.168.1.1'; RouteMetric = 10 }
    }
    foreach ($record in $script:routes.Values) {
        [pscustomobject]@{ DestinationPrefix = $record.Prefix; InterfaceIndex = 21;
            NextHop = '192.168.1.1'; RouteMetric = 5; Protocol = 'NetMgmt' }
    }
}
function Add-PersistentManagedRoute {
    param($Ip, $Gateway, $Kind, [int]$PrefixLength = 32, $ActiveRouteIndex, $AdoptableRouteIndex)
    $record = [pscustomobject]@{ Prefix = "$Ip/$PrefixLength"; InterfaceIndex = 21; NextHop = '192.168.1.1';
        Metric = 5; Kind = $Kind; LastSeen = (Get-Date).ToUniversalTime().ToString('o') }
    $script:routes[$record.Prefix] = $record
    return [pscustomobject]@{ Ok = $true; Created = $true; Record = $record }
}
function Resolve-DomainMap {
    param($Domains, $DnsServers)
    $result = @{}
    foreach ($domain in $Domains) {
        $ip = switch ($domain) {
            'publisher.example' { '198.51.100.1' }
            'cdn.publisher.example' { '198.51.100.2' }
            'shared-a.example' { '198.51.100.11' }
            'shared-b.example' { '198.51.100.11' }
            'rotate.example' { if ($script:phase -eq 1) { '198.51.100.12' } else { '198.51.100.13' } }
            default { '203.0.113.1' }
        }
        $result[$domain] = @($ip)
    }
    return ,$result
}
function Get-DnsClientNrptRule { [CmdletBinding()] param(); return @() }
function Sync-ManagedNrptRules {
    param($Namespaces, $NameServers, $PreviousRuleNames)
    $script:namespaces = @($Namespaces)
    return @('test-rule')
}
function Resolve-DnsName {
    [CmdletBinding()] param($Name, $Type, [switch]$DnsOnly, [switch]$QuickTimeout)
    [pscustomobject]@{ Type = 'A'; IPAddress = '203.0.113.1' }
}
function Remove-RouteRecords {
    param($Records, $ActiveRouteObjectIndex, $PersistentRouteObjectIndex)
    foreach ($record in $Records) { [void]$script:routes.Remove($record.Prefix) }
}
function Register-RouteMonitorTask {}
function Rollback-CurrentRun { param($Routes); throw 'Unexpected rollback in mocked apply' }
'@
$assertions = @'
$saved = Read-ManagedState
foreach ($domain in @('www.ncbi.nlm.nih.gov', 'pubmed.ncbi.nlm.nih.gov', 'pmc.ncbi.nlm.nih.gov',
    'matrix.work.example', 'livekit-jwt.call.matrix.org')) {
    if ($domain -notin $saved.MonitorDomains) { throw "Service omitted from monitor: $domain" }
}
foreach ($namespace in @('.ncbi.nlm.nih.gov', 'ncbi.nlm.nih.gov', '.element.io', '.matrix.org', 'matrix.work.example')) {
    if ($namespace -notin $script:namespaces) { throw "Service omitted from NRPT: $namespace" }
}
if ($script:phase -eq 1) {
    foreach ($prefix in @('198.51.100.1/32', '198.51.100.2/32', '198.51.100.11/32', '198.51.100.12/32', '192.0.2.0/24')) {
        if (-not $script:routes.ContainsKey($prefix)) { throw "User route not installed: $prefix" }
    }
    if ('.publisher.example' -notin $saved.MonitorSuffixes) { throw 'User zone not monitored' }
} else {
    foreach ($prefix in @('198.51.100.1/32', '198.51.100.2/32', '192.0.2.0/24')) {
        if ($script:routes.ContainsKey($prefix)) { throw "Removed entry retained a route: $prefix" }
    }
    foreach ($prefix in @('198.51.100.11/32', '198.51.100.12/32', '198.51.100.13/32')) {
        if (-not $script:routes.ContainsKey($prefix)) { throw "Shared or rotating route lost: $prefix" }
    }
    if ('.publisher.example' -in $saved.MonitorSuffixes -or '.publisher.example' -in $script:namespaces) {
        throw 'Removed zone still monitored or sent to NRPT'
    }

    # Exercise one real monitor iteration and its state save with fake peers.
    $MonitorStateFile = Join-Path $PSScriptRoot 'monitor-state.json'
    function Write-MonitorLog { param($Message) }
    function Get-DnsClientCache { [CmdletBinding()] param(); return @() }
    function Get-ElementRemoteAddresses { return @('198.51.100.40') }
    function Remove-MonitorRouteRecord { param($Record); [void]$script:routes.Remove($Record.Prefix) }
    function New-NetRoute {
        [CmdletBinding()] param($DestinationPrefix, $InterfaceIndex, $NextHop, $RouteMetric, $PolicyStore)
        $script:routes[$DestinationPrefix] = [pscustomobject]@{ Prefix = $DestinationPrefix; InterfaceIndex = $InterfaceIndex;
            NextHop = $NextHop; Metric = $RouteMetric; Kind = 'Monitor' }
    }
    function Start-Sleep { param($Seconds); throw 'test: monitor iteration finished' }
    $dynamicRecords = @(
        [pscustomobject]@{ Prefix = '198.51.100.11/32'; InterfaceIndex = 21; NextHop = '192.168.1.1'; Metric = 5;
            Kind = 'Monitor'; Domain = 'shared-a.example'; LastSeen = (Get-Date).ToUniversalTime().ToString('o') },
        [pscustomobject]@{ Prefix = '198.51.100.41/32'; InterfaceIndex = 21; NextHop = '192.168.1.1'; Metric = 5;
            Kind = 'Monitor'; Domain = 'cdn.publisher.example'; LastSeen = (Get-Date).ToUniversalTime().ToString('o') },
        [pscustomobject]@{ Prefix = '198.51.100.42/32'; InterfaceIndex = 21; NextHop = '192.168.1.1'; Metric = 5;
            Kind = 'Element'; Domain = ''; LastSeen = (Get-Date).ToUniversalTime().AddHours(-25).ToString('o') }
    )
    foreach ($record in $dynamicRecords) {
        if (-not $script:routes.ContainsKey($record.Prefix)) { $script:routes[$record.Prefix] = $record }
    }
    @{ Routes = $dynamicRecords } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $MonitorStateFile
    $finished = $false
    try { Start-RouteMonitor } catch {
        if ($_.Exception.Message -ne 'test: monitor iteration finished') { throw }
        $finished = $true
    }
    if (-not $finished) { throw 'Monitor did not complete an iteration' }
    $monitor = Read-MonitorState
    $peer = @($monitor.Routes | Where-Object Prefix -eq '198.51.100.40/32')
    if ($peer.Count -ne 1 -or $peer[0].Kind -ne 'Element' -or $peer[0].Domain) { throw 'Element peer was not saved as an IP-only route' }
    if (-not $script:routes.ContainsKey('198.51.100.11/32')) { throw 'Monitor removed a shared IP adopted by persistent configuration' }
    foreach ($prefix in @('198.51.100.41/32', '198.51.100.42/32')) {
        if ($script:routes.ContainsKey($prefix)) { throw "Obsolete dynamic route survived: $prefix" }
    }
}
'@
try {
    New-Item -ItemType Directory -Path $casePath | Out-Null
    $wrapper = Join-Path $casePath 'mock_apply.ps1'
    [IO.File]::WriteAllText($wrapper, $prefix + $mocks + "`r`n" + $main + "`r`n" + $assertions, [Text.UTF8Encoding]::new($true))
    $configFile = Join-Path $casePath 'bypass_domains.txt'
    Set-Content -LiteralPath (Join-Path $casePath 'phase.txt') -Value '1'
    Set-Content -LiteralPath $configFile -Value @('.publisher.example', 'shared-a.example', 'rotate.example', '192.0.2.0/24')
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wrapper 2>&1
    if ($LASTEXITCODE) { throw "First apply failed: $output" }
    Set-Content -LiteralPath (Join-Path $casePath 'phase.txt') -Value '2'
    Set-Content -LiteralPath $configFile -Value @('shared-b.example', 'rotate.example')
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wrapper 2>&1
    if ($LASTEXITCODE) { throw "Re-apply failed: $output" }
    Write-Host 'PASS: mocked apply and monitor, service/user DNS and routes, removal, shared IPs, rotation, Element peers and expiry'
} finally {
    $absolute = [IO.Path]::GetFullPath($casePath)
    if (-not $absolute.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Temporary path escaped tests directory'
    }
    if (Test-Path -LiteralPath $absolute) { Remove-Item -LiteralPath $absolute -Recurse -Force }
}
