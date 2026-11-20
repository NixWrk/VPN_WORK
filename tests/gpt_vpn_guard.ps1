# Tests the real -Plan entry point with synthetic adapters and no WFP writes.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot -Parent) 'gpt_vpn_guard.ps1'
$casePath = Join-Path $PSScriptRoot ('gpt-guard-' + [guid]::NewGuid().ToString('N'))
$absolute = [IO.Path]::GetFullPath($casePath)
if (-not $absolute.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary path escaped tests directory'
}
try {
    New-Item -ItemType Directory -Path $absolute | Out-Null
    $copy = Join-Path $absolute 'gpt_vpn_guard.ps1'
    Copy-Item -LiteralPath $source -Destination $copy
    $runner = Join-Path $absolute 'plan.ps1'
    @'
param([string]$Scenario)
$ErrorActionPreference = 'Stop'
$env:USERPROFILE = $PSScriptRoot
function Get-NetAdapter {
    param([switch]$IncludeHidden)
    $office = if ($Scenario -eq 'Disconnected') { 'Disconnected' } else { 'Up' }
    [pscustomobject]@{Name='Wi-Fi'; InterfaceDescription='Intel(R) Wi-Fi 6E AX211'; Status='Up'; HardwareInterface=$true; InterfaceType=71; InterfaceIndex=1; InterfaceGuid='11111111-1111-1111-1111-111111111111'}
    [pscustomobject]@{Name='ZeroTier'; InterfaceDescription='ZeroTier Virtual Port'; Status='Up'; HardwareInterface=$false; InterfaceType=6; InterfaceIndex=2; InterfaceGuid='22222222-2222-2222-2222-222222222222'}
    [pscustomobject]@{Name='Other VPN'; InterfaceDescription='TAP-Windows Adapter V9'; Status='Up'; HardwareInterface=$false; InterfaceType=53; InterfaceIndex=3; InterfaceGuid='33333333-3333-3333-3333-333333333333'}
    [pscustomobject]@{Name='Office tunnel'; InterfaceDescription='WireGuard Tunnel'; Status=$office; HardwareInterface=$false; InterfaceType=131; InterfaceIndex=4; InterfaceGuid='3be596aa-8a8e-4839-9500-2961a25e179c'}
    [pscustomobject]@{Name='WSL'; InterfaceDescription='Hyper-V Virtual Ethernet Adapter'; Status='Up'; HardwareInterface=$false; InterfaceType=53; InterfaceIndex=5; InterfaceGuid='44444444-4444-4444-4444-444444444444'}
}
function Get-NetRoute {
    param([string]$PolicyStore)
    if ($PolicyStore -ne 'ActiveStore') { throw 'VPN selection requires live routes' }
    [pscustomobject]@{InterfaceIndex=1; DestinationPrefix='0.0.0.0/0'; RouteMetric=0; InterfaceMetric=30}
    [pscustomobject]@{InterfaceIndex=2; DestinationPrefix='0.0.0.0/0'; RouteMetric=0; InterfaceMetric=10}
    if ($Scenario -in @('OverlayWins', 'V6', 'OnlyHalf', 'Ambiguous')) {
        if ($Scenario -eq 'V6') { [pscustomobject]@{InterfaceIndex=4; DestinationPrefix='::/0'; RouteMetric=4; InterfaceMetric=1} }
        if ($Scenario -in @('OnlyHalf', 'Ambiguous')) { [pscustomobject]@{InterfaceIndex=3; DestinationPrefix='0.0.0.0/1'; RouteMetric=500; InterfaceMetric=5} }
        if ($Scenario -eq 'Ambiguous') {
            [pscustomobject]@{InterfaceIndex=3; DestinationPrefix='128.0.0.0/1'; RouteMetric=500; InterfaceMetric=5}
            [pscustomobject]@{InterfaceIndex=4; DestinationPrefix='128.0.0.0/1'; RouteMetric=504; InterfaceMetric=1}
        }
        return
    }
    foreach ($prefix in '0.0.0.0/1','128.0.0.0/1') {
        [pscustomobject]@{InterfaceIndex=3; DestinationPrefix=$prefix; RouteMetric=500; InterfaceMetric=5}
    }
}
function Get-ScheduledTask { return $null }
function Start-Process { throw 'Plan tried to elevate' }
function Add-Type { throw 'Plan tried to load the WFP installer' }
function Read-Host { throw 'Plan tried to prompt' }
function Register-ScheduledTask { throw 'Plan modified the startup task' }
function Start-ScheduledTask { throw 'Plan started the background task' }
function Unregister-ScheduledTask { throw 'Plan modified the startup task' }
$guard = Join-Path $PSScriptRoot 'gpt_vpn_guard.ps1'
if ($Scenario -eq 'ManualList') {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($guard, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ($errors -join "`n") }
    $needed = @('Get-VpnAdapterExclusion','Test-VpnPathAdapter','Get-VpnPathAdapters','Write-GuardAdapterList','Select-GuidedVpnAdapters')
    foreach ($definition in $ast.EndBlock.Statements | Where-Object Name -in $needed) {
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    $adapters = @(Get-NetAdapter | Sort-Object Name)
    $script:answers = @(([array]::IndexOf($adapters.Name, 'ZeroTier') + 1), ([array]::IndexOf($adapters.Name, 'Other VPN') + 1))
    $script:promptCount = 0
    function Read-Host {
        $answer = $script:answers[$script:promptCount]
        $script:promptCount++
        return [string]$answer
    }
    $chosen = @(Select-GuidedVpnAdapters $adapters)
    if ($script:promptCount -ne 2 -or $chosen.Count -ne 1 -or $chosen[0].Name -ne 'Other VPN') { throw 'Visible ZeroTier was selectable.' }
    exit 0
}
switch ($Scenario) {
    'ExplicitZeroTier' { & $guard -Plan -VpnAdapter 'ZeroTier' }
    'Physical' { & $guard -Plan -VpnAdapter 'Wi-Fi' }
    'HyperV' { & $guard -Plan -VpnAdapter 'WSL' }
    'Missing' { & $guard -Plan -VpnAdapter 'Missing VPN' }
    'Disconnected' { & $guard -Plan -VpnAdapter 'Office tunnel' }
    'Guid' { & $guard -Plan -VpnAdapter '3be596aa-8a8e-4839-9500-2961a25e179c' }
    'Multiple' { & $guard -Plan -VpnAdapter 'Other VPN', 'Office tunnel' }
    'BlockAll' { & $guard -Plan -BlockAll }
    'ExplicitAuto' { & $guard -Plan -Auto }
    'PlanOnlyChoose' { & $guard -Plan -Guided -ChooseVpn }
    default { & $guard -Plan }
}
exit $LASTEXITCODE
'@ | Set-Content -LiteralPath $runner -Encoding UTF8
    $private = Join-Path $absolute '.codex-chatgpt-web\versions\9.0\runtime'
    New-Item -ItemType Directory -Path $private -Force | Out-Null
    New-Item -ItemType File -Path (Join-Path $private 'bun.exe') | Out-Null
    $browser = Join-Path $absolute 'Browser With Spaces.exe'
    New-Item -ItemType File -Path $browser | Out-Null

    function Invoke-Scenario([string]$Name) {
        $output = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $runner $Name) -join "`n"
        return [pscustomobject]@{ Code = $LASTEXITCODE; Output = $output }
    }

    $auto = Invoke-Scenario 'Auto'
    if ($auto.Code -ne 0) { throw "Automatic mode failed: $($auto.Output)" }
    foreach ($expected in @('VPN interface: Other VPN', 'Mode: auto', 'runtime\bun.exe')) {
        if ($auto.Output -notmatch [regex]::Escape($expected)) { throw "Automatic mode missed '$expected': $($auto.Output)" }
    }
    if ($auto.Output -match 'VPN interface: (Wi-Fi|WSL|ZeroTier|Office tunnel)') { throw "Inactive or untrusted adapter accepted: $($auto.Output)" }
    $manual = Invoke-Scenario 'ManualList'
    foreach ($visible in @('ZeroTier Virtual Port','Wi-Fi','Hyper-V Virtual Ethernet Adapter','ifIndex','GUID')) {
        if ($manual.Code -ne 0 -or $manual.Output -notmatch [regex]::Escape($visible)) {
            throw "Manual adapter list omitted $visible or accepted ZeroTier: $($manual.Output)"
        }
    }

    foreach ($scenario in @('OverlayWins', 'OnlyHalf', 'Ambiguous')) {
        $result = Invoke-Scenario $scenario
        if ($result.Code -ne 0 -or $result.Output -notmatch 'No VPN exception' -or $result.Output -match 'VPN interface:') {
            throw "Unsafe route accepted in $scenario ($($result.Output))"
        }
    }
    $ipv6 = Invoke-Scenario 'V6'
    if ($ipv6.Code -ne 0 -or $ipv6.Output -notmatch 'VPN interface: Office tunnel' -or $ipv6.Output -match 'VPN interface: ZeroTier') {
        throw "IPv6 default route not honored: $($ipv6.Output)"
    }

    $many = Invoke-Scenario 'Multiple'
    if ($many.Code -ne 0 -or $many.Output -notmatch 'VPN interface: Office tunnel' -or
        $many.Output -notmatch 'VPN interface: Other VPN' -or $many.Output -notmatch 'Mode: adapters') {
        throw "Several VPN adapters at once are not supported: $($many.Output)"
    }

    foreach ($scenario in @('Physical', 'HyperV', 'ExplicitZeroTier')) {
        $result = Invoke-Scenario $scenario
        if ($result.Code -ne 1 -or $result.Output -notmatch 'virtual VPN adapter') {
            throw "Unsafe adapter accepted: $scenario ($($result.Output))"
        }
    }

    foreach ($scenario in @('Missing', 'Disconnected')) {
        $result = Invoke-Scenario $scenario
        if ($result.Code -ne 0 -or $result.Output -notmatch 'not connected' -or
            $result.Output -notmatch 'No VPN exception' -or $result.Output -match 'VPN interface:') {
            throw "Scenario $scenario did not fail closed: $($result.Output)"
        }
    }

    $guid = Invoke-Scenario 'Guid'
    if ($guid.Code -ne 0 -or $guid.Output -notmatch 'VPN interface: Office tunnel') {
        throw "Wrong GUID selection: $($guid.Output)"
    }

    $blockAll = Invoke-Scenario 'BlockAll'
    if ($blockAll.Code -ne 0 -or $blockAll.Output -notmatch 'Mode: blockall' -or
        $blockAll.Output -notmatch 'No VPN exception' -or $blockAll.Output -match 'VPN interface:') {
        throw "Block-all mode is wrong: $($blockAll.Output)"
    }

    $explicitAuto = Invoke-Scenario 'ExplicitAuto'
    if ($explicitAuto.Code -ne 0 -or $explicitAuto.Output -notmatch 'VPN interface: Other VPN') {
        throw "Explicit -Auto lost the automatic detection: $($explicitAuto.Output)"
    }
    if ((Invoke-Scenario 'PlanOnlyChoose').Code -ne 0) { throw 'Plan with manual selection prompted or failed.' }

    $config = Join-Path $absolute 'gpt_vpn_guard.local.json'
    @{Mode='auto'; VpnAdapters=@(); Programs=@($browser)} | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding UTF8
    $output = (Invoke-Scenario 'Auto').Output
    if ($output -notlike "*$browser*") { throw "Browser with spaces not honored: $output" }

    @{Mode='adapters'; VpnAdapters=@('Other VPN', 'Office tunnel')} | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding UTF8
    $saved = Invoke-Scenario 'Auto'
    if ($saved.Code -ne 0 -or $saved.Output -notmatch 'Mode: adapters' -or
        $saved.Output -notmatch 'VPN interface: Other VPN' -or $saved.Output -notmatch 'VPN interface: Office tunnel' -or
        $saved.Output -match 'VPN interface: ZeroTier') {
        throw "Saved adapter list not honored: $($saved.Output)"
    }

    @{VpnAdapter='Other VPN'} | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding UTF8
    $legacy = Invoke-Scenario 'Auto'
    if ($legacy.Code -ne 0 -or $legacy.Output -notmatch 'VPN interface: Other VPN' -or $legacy.Output -notmatch 'Mode: adapters') {
        throw "Legacy single adapter config not honored: $($legacy.Output)"
    }

    @{Mode='sideways'} | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding UTF8
    $invalidMode = Invoke-Scenario 'Auto'
    if ($invalidMode.Code -ne 1 -or $invalidMode.Output -notmatch 'Invalid Mode') {
        throw "Invalid mode accepted: $($invalidMode.Output)"
    }

    @{Programs=@('C:\missing\browser.exe')} | ConvertTo-Json | Set-Content -LiteralPath $config -Encoding UTF8
    $invalidProgram = Invoke-Scenario 'Auto'
    if ($invalidProgram.Code -ne 1 -or $invalidProgram.Output -notmatch 'existing executable') {
        throw "Invalid executable accepted: $($invalidProgram.Output)"
    }

    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
    $migration = $ast.EndBlock.Statements | Where-Object Name -eq 'Read-GuardPolicyForMigration'
    . ([scriptblock]::Create($migration.Extent.Text))
    $TaskName = 'test guard'
    $script:taskOwner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    function Export-ScheduledTask {
        param([string]$TaskName, [string]$TaskPath)
        return "<Task><Principals><Principal><UserId>$script:taskOwner</UserId></Principal></Principals></Task>"
    }
    function Test-GuardRuntimePath { return $true }
    function Read-ApprovedGuardPolicy { return @{ Mode = 'adapters'; Programs = @($browser) } }
    $scheduled = [pscustomobject]@{
        Settings = @{ Enabled = $true }
        Triggers = @(@{ Enabled = $true; CimClass = @{ CimClassName = 'MSFT_TaskLogonTrigger' } })
        Principal = @{ UserId = 'short-account-name' }
        Actions = @(@{ Execute = (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')
            WorkingDirectory = $absolute; Arguments = "-File `"$absolute\gpt_vpn_guard_watch.ps1`"" })
    }
    $migrated = Read-GuardPolicyForMigration $scheduled
    if ($migrated.Mode -ne 'adapters' -or $migrated.Programs[0] -ne $browser) { throw 'Approved migration policy was not preserved.' }
    $script:taskOwner = 'S-1-0-0'
    if (Read-GuardPolicyForMigration $scheduled) { throw 'Another user task was accepted.' }

    Write-Host 'PASS: VPN route selection, fail-closed planning, and migration preserving approved policy and task ownership'
} finally {
    if (Test-Path -LiteralPath $absolute) { Remove-Item -LiteralPath $absolute -Recurse -Force }
}
