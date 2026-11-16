# Exercise migration with fake route commands and real temporary state files.
# No adapter, DNS, scheduled task or machine route is changed.
$ErrorActionPreference = "Stop"
$tokens = $null
$errors = $null
$source = Join-Path (Split-Path $PSScriptRoot -Parent) "split_tunnel.ps1"
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @("Get-RouteIdentity", "Update-ManagedGateway", "Set-MonitorRouteGateway")) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "Missing function $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$RouteMetric = 5
$script:currentGateway = [pscustomobject]@{ IfIndex = 21; Gateway = "192.168.1.1"; Desc = "Wi-Fi" }
$script:routes = @{}
$script:removed = @()
$script:removedDynamic = @()
$script:failPrefix = ""
$script:gatewayDisappears = $false
function Find-RealGateway {
    if ($script:gatewayDisappears) { return $null }
    return $script:currentGateway
}
function Get-NetRoute {
    [CmdletBinding()]
    param([string]$AddressFamily, [string]$PolicyStore)
    return @($script:routes.Values)
}
function Write-MonitorLog { param([string]$Message) }
function Remove-RouteRecords {
    param($Records)
    foreach ($record in @($Records)) {
        $id = Get-RouteIdentity -Prefix $record.Prefix -InterfaceIndex $record.InterfaceIndex -NextHop $record.NextHop
        $script:removed += $id
        [void]$script:routes.Remove($id)
    }
}
function Remove-MonitorRouteRecord { param($Record); $script:removedDynamic += $Record }
function Add-PersistentManagedRoute {
    param([string]$Ip, [int]$PrefixLength, $Gateway, [string]$Kind, $ActiveRouteIndex, $AdoptableRouteIndex)
    $prefix = "$Ip/$PrefixLength"
    if ($prefix -eq $script:failPrefix) {
        return [pscustomobject]@{ Ok = $false; Message = "simulated route failure" }
    }
    $id = Get-RouteIdentity -Prefix $prefix -InterfaceIndex $Gateway.IfIndex -NextHop $Gateway.Gateway
    $created = -not $ActiveRouteIndex.ContainsKey($id)
    $record = [pscustomobject]@{
        Prefix = $prefix; InterfaceIndex = $Gateway.IfIndex; NextHop = $Gateway.Gateway
        Metric = 5; Kind = $Kind; LastSeen = "new"
    }
    if ($created) {
        $script:routes[$id] = [pscustomobject]@{
            DestinationPrefix = $prefix; InterfaceIndex = $Gateway.IfIndex; NextHop = $Gateway.Gateway; RouteMetric = 5
        }
    } elseif (-not $AdoptableRouteIndex.ContainsKey($id)) { $record = $null }
    return [pscustomobject]@{ Ok = $true; Created = $created; Record = $record }
}
function New-TestConfiguration {
    return [pscustomobject]@{
        Version = 3; UpdatedAt = "old"; Gateway = "192.168.1.1"; InterfaceIndex = 11; InterfaceDescription = "Wi-Fi"
        DnsServers = @("8.8.8.8"); NrptRuleNames = @("keep-rule"); MonitorDomains = @("ozon.ru"); MonitorSuffixes = @(".ru")
        Routes = @(
            [pscustomobject]@{ Prefix = "198.51.100.12/32"; InterfaceIndex = 11; NextHop = "192.168.1.1"; Metric = 5; Kind = "Suffix bypass"; LastSeen = "keep-time"; Domains = @("ozon.ru") },
            [pscustomobject]@{ Prefix = "95.163.51.0/24"; InterfaceIndex = 11; NextHop = "192.168.1.1"; Metric = 5; Kind = "Static"; LastSeen = "keep-time" }
        )
    }
}
$casePath = Join-Path $PSScriptRoot ("gateway-" + [guid]::NewGuid().ToString("N"))
$casePath = [IO.Path]::GetFullPath($casePath)
$testsRoot = [IO.Path]::GetFullPath($PSScriptRoot) + [IO.Path]::DirectorySeparatorChar
if (-not $casePath.StartsWith($testsRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Unsafe temporary test path" }
try {
    New-Item -ItemType Directory -Path $casePath | Out-Null
    $StateFile = Join-Path $casePath "state.json"
    $original = New-TestConfiguration
    $updated = Update-ManagedGateway -Configuration $original -Gateway $script:currentGateway
    $saved = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
    if ($saved.InterfaceIndex -ne 21 -or $saved.Routes.Count -ne 2 -or
        @($saved.Routes | Where-Object InterfaceIndex -ne 21).Count -gt 0 -or
        $saved.NrptRuleNames[0] -ne "keep-rule" -or $saved.Routes[0].LastSeen -ne "keep-time" -or
        $saved.Routes[0].Domains[0] -ne "ozon.ru") {
        throw "Interface migration lost routes, timestamps or DNS configuration"
    }
    $script:removed = @()
    [void](Update-ManagedGateway -Configuration $updated -Gateway $script:currentGateway)
    if ($script:removed.Count -gt 0) { throw "Unchanged gateway rewrote routes" }

    # Windows may have already moved a persistent route to the new index.
    # Adopt it without adding a duplicate or removing it as stale.
    $script:removed = @()
    $partial = New-TestConfiguration
    $partial.Routes[0].InterfaceIndex = 21
    $updated = Update-ManagedGateway -Configuration $partial -Gateway $script:currentGateway
    $newId = "198.51.100.12/32|21|192.168.1.1"
    if ($newId -in $script:removed -or -not $script:routes.ContainsKey($newId) -or $updated.Routes.Count -ne 2) {
        throw "Already-renumbered managed routes were lost"
    }

    $dynamic = [pscustomobject]@{
        Prefix = "203.0.113.9/32"; InterfaceIndex = 11; NextHop = "192.168.1.1"; Metric = 5
        Domain = "cached.ru"; LastSeen = "keep-dynamic-time"
    }
    $moved = Set-MonitorRouteGateway -Record $dynamic -Gateway $script:currentGateway
    if ($moved.InterfaceIndex -ne 21 -or $moved.Domain -ne "cached.ru" -or
        $moved.LastSeen -ne "keep-dynamic-time" -or $script:removedDynamic.Count -ne 1) {
        throw "Dynamic host was discarded instead of migrated"
    }

    $script:currentGateway = [pscustomobject]@{ IfIndex = 30; Gateway = "192.168.2.1"; Desc = "Ethernet" }
    $moved = Update-ManagedGateway -Configuration $updated -Gateway $script:currentGateway
    if ($moved.Gateway -ne "192.168.2.1" -or $moved.InterfaceIndex -ne 30 -or
        @($moved.Routes | Where-Object { $_.NextHop -ne "192.168.2.1" -or $_.InterfaceIndex -ne 30 }).Count -gt 0) {
        throw "Switching physical networks retained the old gateway"
    }
    $script:currentGateway = [pscustomobject]@{ IfIndex = 21; Gateway = "192.168.1.1"; Desc = "Wi-Fi" }

    # Failure after one new route must roll back that route and preserve state.
    $before = [IO.File]::ReadAllText($StateFile)
    $script:routes = @{}
    $script:removed = @()
    $script:failPrefix = "95.163.51.0/24"
    $failed = $false
    try { [void](Update-ManagedGateway -Configuration (New-TestConfiguration) -Gateway $script:currentGateway) } catch { $failed = $true }
    if (-not $failed -or $script:routes.Count -ne 0 -or [IO.File]::ReadAllText($StateFile) -ne $before -or
        "198.51.100.12/32|11|192.168.1.1" -in $script:removed) {
        throw "Failed migration removed old routes or changed state"
    }
    $script:failPrefix = ""
    $script:gatewayDisappears = $true
    $failed = $false
    try { [void](Update-ManagedGateway -Configuration (New-TestConfiguration) -Gateway $script:currentGateway) } catch { $failed = $true }
    if (-not $failed -or $script:routes.Count -ne 0 -or [IO.File]::ReadAllText($StateFile) -ne $before) {
        throw "Gateway loss during migration committed stale indices"
    }
    $script:gatewayDisappears = $false
    function Move-Item {
        [CmdletBinding()]
        param([string]$LiteralPath, [string]$Destination, [switch]$Force)
        throw "simulated state write failure"
    }
    $failed = $false
    try { [void](Update-ManagedGateway -Configuration (New-TestConfiguration) -Gateway $script:currentGateway) } catch { $failed = $true }
    if (-not $failed -or $script:routes.Count -ne 0 -or [IO.File]::ReadAllText($StateFile) -ne $before) {
        throw "State write failure was not rolled back"
    }
    Write-Host "PASS: automatic index/gateway migration, dynamic hosts, no-op, adopted routes and rollback on route/network/state failures"
} finally {
    if (Test-Path -LiteralPath $casePath) { Remove-Item -LiteralPath $casePath -Recurse -Force }
}
