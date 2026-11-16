# Per-PC Element discovery, with fake processes/connections and JSON fixtures.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'split_tunnel.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in @('ConvertTo-DomainName', 'ConvertTo-DomainList', 'Find-ElementDomains',
    'Get-ElementRemoteAddresses', 'Test-MonitorIpv4', 'Set-MonitorRouteGateway')) {
    $definition = $ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true) | Select-Object -First 1
    . ([scriptblock]::Create($definition.Extent.Text))
}
$casePath = Join-Path $PSScriptRoot ('element-' + [guid]::NewGuid().ToString('N'))
$previousAppData = $env:APPDATA
$previousConfig = $env:ELEMENT_DESKTOP_CONFIG_JSON
$sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
$script:noElement = $false
function Get-CimInstance {
    [CmdletBinding()] param($ClassName, $Filter)
    [pscustomobject]@{ SessionId = $sessionId; CommandLine = ('Element.exe --config="' + (Join-Path $casePath 'custom.json') + '"') }
    [pscustomobject]@{ SessionId = $sessionId; CommandLine = ('Element.exe --profile-dir "' + (Join-Path $casePath 'custom profile') + '"') }
}
function Get-Process {
    [CmdletBinding()] param($Name)
    if ($script:noElement) { return }
    [pscustomobject]@{ Id = 123; SessionId = $sessionId }
    [pscustomobject]@{ Id = 124; SessionId = $sessionId }
    [pscustomobject]@{ Id = 999; SessionId = $sessionId + 1 }
}
function Get-NetTCPConnection {
    [CmdletBinding()] param($OwningProcess, $State)
    if (($OwningProcess -join ',') -ne '123,124' -or ($State -join ',') -ne 'Established,SynSent') {
        throw 'Connection discovery included another session or omitted connection attempts'
    }
    foreach ($ip in @('203.0.113.7', '203.0.113.7', '198.51.100.9', '::1', '2001:db8::1',
        '127.0.0.1', '10.1.1.1', '192.168.1.2', '172.16.1.1', '169.254.1.2', '100.64.1.2', '224.1.1.1')) {
        [pscustomobject]@{ RemoteAddress = $ip }
    }
}
function Remove-MonitorRouteRecord { param($Record) }
try {
    New-Item -ItemType Directory -Path $casePath | Out-Null
    $env:APPDATA = $casePath
    foreach ($profile in @('Element', 'Element-work', 'Riot', 'custom profile')) {
        $directory = Join-Path $casePath $profile
        New-Item -ItemType Directory -Path $directory | Out-Null
        [ordered]@{ default_server_config = @{ 'm.homeserver' = @{ base_url = "https://$($profile.Replace(' ', '-')).example.org" } } } |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $directory 'config.json') -Encoding UTF8
    }
    '{"default_hs_url":"https://custom.example.org","element_call":{"url":"https://calls.example.org"},"org.matrix.msc4143.rtc_foci":[{"livekit_service_url":"https://rtc.example.org"}]}' |
        Set-Content -LiteralPath (Join-Path $casePath 'custom.json') -Encoding UTF8
    $env:ELEMENT_DESKTOP_CONFIG_JSON = Join-Path $casePath 'env.json'
    '{"default_is_url":"https://identity.example.org"}' | Set-Content -LiteralPath $env:ELEMENT_DESKTOP_CONFIG_JSON -Encoding UTF8
    $domains = @(Find-ElementDomains)
    foreach ($expected in @('element.example.org', 'element-work.example.org', 'riot.example.org', 'custom-profile.example.org',
        'custom.example.org', 'calls.example.org', 'rtc.example.org', 'identity.example.org')) {
        if ($expected -notin $domains) { throw "Local Element endpoint missed: $expected" }
    }
    if ($domains.Count -ne 8) { throw "Unexpected local Element hosts: $domains" }
    if ((@(Get-ElementRemoteAddresses) -join ',') -ne '203.0.113.7,198.51.100.9') { throw 'Public peer detection failed' }
    $script:noElement = $true
    if (@(Get-ElementRemoteAddresses).Count) { throw 'Connections discovered without Element' }
    $RouteMetric = 5
    $record = [pscustomobject]@{ Prefix = '203.0.113.7/32'; Domain = ''; Kind = 'Element'; LastSeen = 'keep-time' }
    $migrated = Set-MonitorRouteGateway -Record $record -Gateway ([pscustomobject]@{ IfIndex = 21; Gateway = '192.168.1.1' })
    if ($migrated.Kind -ne 'Element' -or $migrated.LastSeen -ne 'keep-time') { throw 'Element route identity lost during gateway migration' }
    Write-Host 'PASS: Element profiles, custom config/profile paths, RTC, per-session TCP peers and LAN exclusions'
} finally {
    $env:APPDATA = $previousAppData
    $env:ELEMENT_DESKTOP_CONFIG_JSON = $previousConfig
    $absolute = [IO.Path]::GetFullPath($casePath)
    if (-not $absolute.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Temporary path escaped tests directory'
    }
    if (Test-Path -LiteralPath $absolute) { Remove-Item -LiteralPath $absolute -Recurse -Force }
}
