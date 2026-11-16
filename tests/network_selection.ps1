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
    "ConvertFrom-NslookupAnswer"
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
    $index = if ($RemoteIPAddress -eq "10.254.254.5") { 73 } else { 11 }
    return [pscustomobject]@{ DestinationPrefix = "$RemoteIPAddress/32"; InterfaceIndex = $index }
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
        "Name: yougile.com", "Addresses: 78.155.198.59", "  77.88.44.55"
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

Write-Host "PASS: VPN DNS discovery, gateway rediscovery, nslookup parsing and service DNS coverage"
