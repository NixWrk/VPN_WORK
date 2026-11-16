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
function Get-CurrentVpnDnsServers { return @('172.19.0.2') }
function Test-DnsDirectViaLan { param($Server, $Gateway); return ($script:phase -lt 3) }
function Test-DnsCandidate { param($Server, [switch]$Report); return ($script:phase -lt 3) }
function Test-DnsViaNrpt { param($Server, [switch]$Report); return $true }
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
    if ($script:phase -ge 3) {
        if (@($DnsServers).Count -ne 0) { throw 'System DNS received an explicit resolver' }
        if ($script:namespaces.Count -gt 0) { throw 'System DNS used before removing old managed NRPT rules' }
        $script:systemLookups++
    }
    $result = @{}
    foreach ($domain in $Domains) {
        if ($script:phase -ge 3 -and $domain -eq 'yandex.ru') {
            $result[$domain] = @()
            continue
        }
        $ip = switch ($domain) {
            'publisher.example' { '198.51.100.1' }
            'cdn.publisher.example' { '198.51.100.2' }
            'shared-a.example' { '198.51.100.11' }
            'shared-b.example' { '198.51.100.11' }
            'rotate.example' { if ($script:phase -eq 1) { '198.51.100.12' } else { '198.51.100.13' } }
            'pubmed.ncbi.nlm.nih.gov' { '203.0.113.42' }
            'xn--90aivcdt6dxbc.xn--p1ai' { '203.0.113.43' }
            default { '203.0.113.1' }
        }
        $result[$domain] = @($ip)
    }
    return ,$result
}
$script:namespaces = @()
$script:systemLookups = 0
if ($script:phase -eq 3) { $script:namespaces = @('.ru') }
function Get-DnsClientNrptRule {
    [CmdletBinding()] param()
    if ($script:phase -eq 3) {
        [pscustomobject]@{ Name = 'test-rule'; Namespace = '.ru'; NameServers = @('8.8.8.8'); DisplayName = 'test'; Comment = $NrptComment }
    }
}
function Sync-ManagedNrptRules {
    param($Namespaces, $NameServers, $PreviousRuleNames)
    $script:namespaces = @($Namespaces)
    if ($script:phase -ge 3) {
        if ($script:phase -eq 4 -or $Namespaces.Count -gt 0 -or $NameServers.Count -gt 0 -or
            'test-rule' -notin $PreviousRuleNames) { throw 'Unexpected NRPT changes in System DNS mode' }
        return
    }
    return @('test-rule')
}
function Resolve-DnsName {
    [CmdletBinding()] param($Name, $Type, [switch]$DnsOnly, [switch]$NoHostsFile, [switch]$QuickTimeout)
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
foreach ($zone in @('.ru', '.xn--p1ai')) {
    if ($zone -notin $saved.MonitorSuffixes) { throw "Zone missing from monitor: $zone" }
}
if (-not $script:routes.ContainsKey('203.0.113.43/32')) { throw 'Direct route for the seeded IDN site is missing' }
foreach ($domain in @('www.ncbi.nlm.nih.gov', 'pubmed.ncbi.nlm.nih.gov', 'pmc.ncbi.nlm.nih.gov',
    'matrix.work.example', 'livekit-jwt.call.matrix.org')) {
    if ($domain -notin $saved.MonitorDomains) { throw "Service omitted from monitor: $domain" }
}
if ($script:phase -lt 3) {
    foreach ($namespace in @('.ru', '.xn--p1ai', '.ncbi.nlm.nih.gov', 'ncbi.nlm.nih.gov', '.element.io', '.matrix.org', 'matrix.work.example')) {
        if ($namespace -notin $script:namespaces) { throw "Service omitted from NRPT: $namespace" }
    }
} else {
    if ($saved.DnsMode -ne 'System' -or $saved.DnsServers.Count -gt 0 -or $saved.NrptRuleNames.Count -gt 0) {
        throw 'System DNS state contains an explicit resolver or NRPT rules'
    }
    if ($script:routes.ContainsKey('8.8.8.8/32')) { throw 'The old direct DNS route was retained' }
    if (-not $script:routes.ContainsKey('203.0.113.42/32')) { throw 'PubMed route was lost when Yandex DNS failed' }
}
if ($script:phase -eq 1) {
    foreach ($prefix in @('198.51.100.1/32', '198.51.100.2/32', '198.51.100.11/32', '198.51.100.12/32', '192.0.2.0/24')) {
        if (-not $script:routes.ContainsKey($prefix)) { throw "User route not installed: $prefix" }
    }
    if ('.publisher.example' -notin $saved.MonitorSuffixes) { throw 'User zone not monitored' }
} elseif ($script:phase -le 3) {
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
    if ($script:phase -eq 3 -and $script:systemLookups -ne 2) { throw 'Monitor did not refresh routes using System DNS' }
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
    Set-Content -LiteralPath (Join-Path $casePath 'phase.txt') -Value '3'
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wrapper 2>&1
    if ($LASTEXITCODE) { throw "DNS fallback from previous config failed: $output" }
    Remove-Item -LiteralPath (Join-Path $casePath 'state.json')
    Set-Content -LiteralPath (Join-Path $casePath 'phase.txt') -Value '4'
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $wrapper 2>&1
    if ($LASTEXITCODE) { throw "DNS fallback on a fresh install failed: $output" }
    Write-Host 'PASS: mocked apply and monitor, explicit and System DNS, shared IPs, rotation, Element peers and expiry'
} finally {
    $absolute = [IO.Path]::GetFullPath($casePath)
    if (-not $absolute.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Temporary path escaped tests directory'
    }
    if (Test-Path -LiteralPath $absolute) { Remove-Item -LiteralPath $absolute -Recurse -Force }
}
