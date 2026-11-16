# Read-only regression tests. Load only the functions under test; the script's
# main section would otherwise request elevation and change network settings.
$ErrorActionPreference = "Stop"
$source = Join-Path (Split-Path $PSScriptRoot -Parent) "split_tunnel.ps1"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $source, [ref]$tokens, [ref]$errors
)
if ($errors.Count -gt 0) { throw "split_tunnel.ps1 has syntax errors" }
foreach ($name in @(
    "Find-RealGateway", "Get-CurrentVpnDnsServers", "Test-DnsCandidate",
    "ConvertFrom-NslookupAnswer", "Test-MonitorIpv4", "Resolve-Ips", "Show-DiagnosticReport"
)) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $name
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "Missing function $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:adapters = @(
    [pscustomobject]@{ InterfaceIndex = 9; Status = "Up"; HardwareInterface = $false; InterfaceDescription = "ZeroTier" },
    [pscustomobject]@{ InterfaceIndex = 11; Status = "Up"; HardwareInterface = $true; InterfaceDescription = "Wi-Fi" },
    [pscustomobject]@{ InterfaceIndex = 73; Status = "Up"; HardwareInterface = $false; InterfaceDescription = "WireGuard Tunnel" },
    [pscustomobject]@{ InterfaceIndex = 74; Status = "Disconnected"; HardwareInterface = $false; InterfaceDescription = "Other VPN" }
)
$script:defaultRoutes = @(
    [pscustomobject]@{ InterfaceIndex = 9; NextHop = "25.255.255.254"; RouteMetric = 9999 },
    [pscustomobject]@{ InterfaceIndex = 11; NextHop = "192.168.1.1"; RouteMetric = 0 }
)
$script:serverAddresses = @{
    9 = @()
    11 = @("192.168.1.1")
    73 = @("10.254.254.5", "0.0.0.0")
    74 = @("203.0.113.53")
}
$VpnHints = @("vpn", "tunnel", "zerotier", "wireguard")

function Get-NetAdapter {
    [CmdletBinding()]
    param([int]$InterfaceIndex)
    if ($PSBoundParameters.ContainsKey("InterfaceIndex")) {
        return $script:adapters | Where-Object InterfaceIndex -eq $InterfaceIndex
    }
    return $script:adapters
}
function Get-NetRoute {
    [CmdletBinding()]
    param([string]$DestinationPrefix)
    if ($DestinationPrefix -eq "0.0.0.0/0") { return $script:defaultRoutes }
}
function Get-NetIPInterface {
    [CmdletBinding()]
    param([string]$AddressFamily, [int]$InterfaceIndex)
    return [pscustomobject]@{ InterfaceMetric = $(if ($InterfaceIndex -eq 11) { 35 } else { 5 }) }
}
function Get-DnsClientServerAddress {
    [CmdletBinding()]
    param([int]$InterfaceIndex, [string]$AddressFamily)
    return [pscustomobject]@{ ServerAddresses = $script:serverAddresses[$InterfaceIndex] }
}
function Find-NetRoute {
    [CmdletBinding()]
    param([string]$RemoteIPAddress)
    $index = switch ($RemoteIPAddress) {
        '10.254.254.5' { 73 }
        '203.0.113.43' { 21 }
        default { 11 }
    }
    return [pscustomobject]@{ DestinationPrefix = "$RemoteIPAddress/32"; InterfaceIndex = $index; NextHop = '192.168.1.1' }
}

$servers = @(Get-CurrentVpnDnsServers)
if ($servers.Count -ne 1 -or $servers[0] -ne "10.254.254.5") {
    throw "VPN DNS discovery missed the adapter without a default route: $($servers -join ', ')"
}
$gateway = Find-RealGateway
if ($gateway.IfIndex -ne 11 -or $gateway.Gateway -ne "192.168.1.1") {
    throw "Physical gateway selection failed"
}

# A saved interface index must not determine the next gateway selection.
$script:adapters = @($script:adapters | Where-Object InterfaceIndex -ne 11) +
    @([pscustomobject]@{ InterfaceIndex = 21; Status = "Up"; HardwareInterface = $true; InterfaceDescription = "Wi-Fi" })
$script:defaultRoutes = @(
    [pscustomobject]@{ InterfaceIndex = 9; NextHop = "25.255.255.254"; RouteMetric = 9999 },
    [pscustomobject]@{ InterfaceIndex = 21; NextHop = "192.168.1.1"; RouteMetric = 0 }
)
$gateway = Find-RealGateway
if ($gateway.IfIndex -ne 21) { throw "Gateway was not rediscovered after its interface index changed" }

# An unavailable physical interface must not cause fallback to a VPN adapter.
$script:adapters = @($script:adapters | Where-Object { -not $_.HardwareInterface })
if (Find-RealGateway) { throw "VPN selected after the physical gateway disappeared" }

$parsed = @(ConvertFrom-NslookupAnswer `
    -Lines @(
        "Server: UnKnown", "Address: 10.254.254.5", "",
        "Name: yougile.com", "Addresses: 78.155.198.59", "  77.88.44.55", "  198.19.0.5"
    ) `
    -Server "10.254.254.5")
if ($parsed.Count -ne 2 -or "10.254.254.5" -in $parsed) {
    throw "nslookup output included the resolver or lost A records"
}
$negative = @(ConvertFrom-NslookupAnswer `
    -Lines @("Server: UnKnown", "Address: 10.254.254.5", "*** query timed out") `
    -Server "10.254.254.5")
if ($negative.Count -ne 0) { throw "nslookup error was mistaken for an A record" }

$DnsProbeName = "example.com"
$DnsCriticalNames = @("yougile.com", "yandex.ru")
$script:unavailableNames = @("yandex.ru")
function Clear-DnsClientCache { [CmdletBinding()] param() }
function Test-DnsServer {
    [CmdletBinding()]
    param([string]$Server, [string]$Name, [switch]$SkipCacheClear)
    return ($Name -notin $script:unavailableNames)
}
function Resolve-IpsWithNslookup {
    [CmdletBinding()]
    param([string]$Domain, [string]$Server)
    return @()
}
if (Test-DnsCandidate -Server "10.254.254.5") {
    throw "A resolver that only answers the generic probe was accepted"
}
$script:unavailableNames = @()
if (-not (Test-DnsCandidate -Server "10.254.254.5")) {
    throw "A resolver covering the managed domains was rejected"
}

function Resolve-DnsName {
    [CmdletBinding()]
    param($Name, $Type, $Server, [switch]$DnsOnly, [switch]$NoHostsFile, [switch]$QuickTimeout)
    if ($PSBoundParameters.ContainsKey('Server')) { throw 'System DNS must not set -Server' }
    if ($Name -eq 'yandex.ru') { throw 'DNS request timed out' }
    [pscustomobject]@{ Type = 'A'; IPAddress = '198.18.0.42' }
    if ($Name -eq 'pubmed.ncbi.nlm.nih.gov') { [pscustomobject]@{ Type = 'A'; IPAddress = '203.0.113.42' } }
    if ($Name -eq 'xn--90aivcdt6dxbc.xn--p1ai') { [pscustomobject]@{ Type = 'A'; IPAddress = '203.0.113.43' } }
}
$answers = @(Resolve-Ips -Domain 'pubmed.ncbi.nlm.nih.gov' -DnsServers @())
if ($answers.Count -ne 1 -or $answers[0] -ne '203.0.113.42') { throw 'System DNS lost the real A record or kept a synthetic address' }
foreach ($domain in @('yandex.ru', 'fake.example')) {
    if (@(Resolve-Ips -Domain $domain -DnsServers @()).Count -gt 0) { throw "Unusable DNS answer was accepted: $domain" }
}

$ConfigFile = 'test-config.txt'
$ApplyLogFile = 'test-apply.log'
$MonitorStateFile = Join-Path $PSScriptRoot 'missing-monitor-state.json'
$MonitorTaskName = 'test'
$NationalBypassSuffixes = @('.ru', '.xn--p1ai')
$BypassZoneProbeNames = @('yandex.ru', 'xn--90aivcdt6dxbc.xn--p1ai')
$SystemDnsProbeNames = $BypassZoneProbeNames + @('pubmed.ncbi.nlm.nih.gov')
$PublicDnsServers = @('8.8.8.8')
$userConfig = @{ Domains = @(); Suffixes = @(); Prefixes = @() }
function Read-ManagedState { return $null }
function Find-ElementDomains { return @() }
function Get-ElementRemoteAddresses { return @() }
function Get-LanDnsServers { param($Gateway); return @('192.168.1.1') }
function Get-ScheduledTask { [CmdletBinding()] param($TaskName) }
function Get-DnsClientNrptRule { [CmdletBinding()] param() }
function Get-DnsClientNrptPolicy {
    [CmdletBinding()] param([switch]$Effective, $Namespace)
    Write-Error 'Test policy absent' -ErrorId 'WIN32 4312'
}
$script:adapters += [pscustomobject]@{ InterfaceIndex = 21; Status = 'Up'; HardwareInterface = $true; InterfaceDescription = 'Wi-Fi' }
$report = Show-DiagnosticReport 6>&1 | Out-String
if ($report -notmatch 'Effective \.ru NRPT policy: no rule returned' -or
    $report -notmatch 'Effective \.xn--p1ai NRPT policy: no rule returned' -or
    $report -notmatch '\[System DNS\] pubmed\.ncbi\.nlm\.nih\.gov  \[OK\]' -or
    $report -notmatch '\[Windows route\] xn--90aivcdt6dxbc\.xn--p1ai -> 203\.0\.113\.43 \[LAN/Wi-Fi gateway\]') {
    throw "Diagnosis did not continue after an absent NRPT rule: $report"
}

Write-Host "PASS: gateway selection, VPN and system DNS, nslookup, synthetic IP filtering and missing NRPT policy"
