# Build and open the one-file package, then stage it in an isolated directory.
# No UAC, scheduled tasks, real configs or network state are changed.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$case = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ('Package check ' + [guid]::NewGuid().ToString('N'))))
if (-not $case.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary packaging path escaped the tests directory.'
}
$originalData = $env:LOCALAPPDATA
$components = @('split_tunnel.ps1', 'gpt_vpn_guard.ps1', 'gpt_vpn_guard_watch.ps1', 'gpt_vpn_filter.cs', 'zotero_proxy.ps1')
try {
    $build = Join-Path $case 'Build sources'
    [void][IO.Directory]::CreateDirectory((Join-Path $build 'launcher'))
    foreach ($name in ($components + @('build_exe.ps1', 'VERSION'))) {
        Copy-Item -LiteralPath (Join-Path $root $name) -Destination $build
    }
    foreach ($name in 'Program.cs', 'Updater.cs', 'BrowserProxy.cs', 'BrowserLan.cs', 'GuardUpgrade.cs', 'InstallUpdate.ps1') {
        Copy-Item -LiteralPath (Join-Path (Join-Path $root 'launcher') $name) -Destination (Join-Path $build 'launcher')
    }
    $exe = Join-Path $case 'Standalone copy\VPN_WORK.exe'
    foreach ($attempt in 1..2) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $build 'build_exe.ps1') -OutputPath $exe
        if ($LASTEXITCODE) { throw "Build attempt $attempt failed." }
    }
    if (@(Get-ChildItem -LiteralPath (Split-Path $exe) -Force).Count -ne 1) { throw 'Distribution requires extra files.' }
    $lines = @(& $exe --verify)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 6) { throw "Package verification failed: $lines" }
    foreach ($name in $components) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ("$name $hash" -notin $lines) { throw "Wrong embedded data: $name" }
    }
    $menu = (@('1', '0', '2', '2', '0', '4', '0', '5', '0', '0', '0') | & $exe --no-update) -join "`n"
    $version = (Get-Content -LiteralPath (Join-Path $root 'VERSION') -Raw).Trim()
    if ($LASTEXITCODE -ne 0 -or $menu -notmatch 'ChatGPT' -or $menu -notmatch 'Zotero' -or $menu -notmatch 'Microsoft Edge' -or
        $menu -notmatch [regex]::Escape("VPN WORK $version")) { throw 'Standalone menu failed.' }
    if ((& $exe --version) -ne $version -or $LASTEXITCODE -ne 0) { throw 'Invalid executable version.' }

    $assembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($exe))
    $program = $assembly.GetType('Program')
    $flags = [Reflection.BindingFlags]'NonPublic,Static'
    $install = $program.GetMethod('Install', $flags)
    $runMenu = [Delegate]::CreateDelegate([Func[Func[string,string,int],int]], $program.GetMethod('RunMenu', $flags))
    $updates = [Delegate]::CreateDelegate([Func[string,Func[bool],bool]], $program.GetMethod('UpdatesMenu', $flags))
    $calls = New-Object 'Collections.Generic.List[string]'
    $fakeScript = [Func[string,string,int]] {
        param($scriptName, $arguments)
        $calls.Add("$scriptName $arguments")
        if ($scriptName -eq 'gpt_vpn_guard.ps1') { return 3 }
        if ($arguments -eq '-Automatic') { return 3 }
        return 0
    }
    $originalIn = [Console]::In
    $originalOut = [Console]::Out
    $scratchOutput = New-Object IO.StringWriter
    try {
        [Console]::SetOut($scratchOutput)
        # Cancel auto once, run it, then use the manual check and cancel removal.
        [Console]::SetIn([IO.StringReader]::new("1`n0`n1`n1`n2`n1`n3`n5`n0`n0`n0`n0`n"))
        if ($runMenu.Invoke($fakeScript) -ne 0 -or ($calls -join ';') -ne
            'split_tunnel.ps1 -Packaged;gpt_vpn_guard.ps1 -Packaged -Guided;zotero_proxy.ps1 -Automatic;split_tunnel.ps1 -Packaged -CheckConfig') {
            throw "Modes dispatched incorrect actions: $calls"
        }
        $preference = [string](Join-Path $case 'Test preferences\disable-auto-update')
        $fakeUpdate = [Func[bool]]{ return $false }
        [Console]::SetIn([IO.StringReader]::new("1`n0`n"))
        if ($updates.Invoke($preference, $fakeUpdate) -or -not (Test-Path -LiteralPath $preference)) { throw 'Disabling updates did not persist.' }
        [Console]::SetIn([IO.StringReader]::new("1`n0`n"))
        if ($updates.Invoke($preference, $fakeUpdate) -or (Test-Path -LiteralPath $preference)) { throw 'Re-enabling updates did not clear the preference.' }
    } finally {
        [Console]::SetIn($originalIn)
        [Console]::SetOut($originalOut)
        $scratchOutput.Dispose()
    }

    $updater = $assembly.GetType('Updater')
    $selectAsset = $updater.GetMethod('NewerAsset', $flags)
    $knownVersion = [version]($version + '.0')
    $next = '{0}.{1}.{2}' -f $knownVersion.Major, $knownVersion.Minor, ($knownVersion.Build + 1)
    $meta = @{ tag_name = "v$next"; draft = $false; prerelease = $false; assets = @(@{
        name='VPN_WORK.exe'; state='uploaded'; size=10; digest=('sha256:' + ('a' * 64));
        browser_download_url="https://github.com/NixWrk/VPN_WORK/releases/download/v$next/VPN_WORK.exe"
    }) }
    $releaseArgs = [object[]]::new(3)
    $releaseArgs[1] = $knownVersion
    $releaseArgs[0] = [Text.Encoding]::UTF8.GetBytes(($meta | ConvertTo-Json -Depth 4 -Compress))
    if (-not $selectAsset.Invoke($null, $releaseArgs) -or $releaseArgs[2].ToString(3) -ne $next) { throw 'Valid release rejected.' }
    $meta.prerelease = $true
    $releaseArgs[0] = [Text.Encoding]::UTF8.GetBytes(($meta | ConvertTo-Json -Depth 4 -Compress))
    if ($selectAsset.Invoke($null, $releaseArgs)) { throw 'Prerelease accepted.' }
    $meta.prerelease = $false
    $meta.tag_name = "v$version"
    $releaseArgs[0] = [Text.Encoding]::UTF8.GetBytes(($meta | ConvertTo-Json -Depth 4 -Compress))
    if ($selectAsset.Invoke($null, $releaseArgs)) { throw 'Same release was selected again.' }
    $meta.tag_name = "v$next"
    $meta.assets[0].browser_download_url = 'https://not-github.example/VPN_WORK.exe'
    $releaseArgs[0] = [Text.Encoding]::UTF8.GetBytes(($meta | ConvertTo-Json -Depth 4 -Compress))
    $rejectedAsset = $false
    try { [void]$selectAsset.Invoke($null, $releaseArgs) } catch { $rejectedAsset = $_.Exception.GetBaseException() -is [IO.InvalidDataException] }
    if (-not $rejectedAsset) { throw 'Untrusted release URL accepted.' }

    $stage = [Delegate]::CreateDelegate([Func[string,string]], $install)
    $stagedRoot = Join-Path $case 'Test Program Files\VPN_WORK'
    [void][IO.Directory]::CreateDirectory((Split-Path $stagedRoot))
    $payload = $stage.Invoke($stagedRoot)
    if ($payload -ne $stage.Invoke($stagedRoot)) { throw 'Staging is not idempotent.' }

    $needsMigration = [Delegate]::CreateDelegate([Func[string,string,string,string,Func[string,byte[]],bool]],
        $assembly.GetType('GuardUpgrade').GetMethod('NeedsTaskUpgrade', $flags))
    $guardFiles = @('gpt_vpn_guard.ps1', 'gpt_vpn_guard_watch.ps1', 'gpt_vpn_filter.cs')
    $resource = [Delegate]::CreateDelegate([Func[string,byte[]]], $program.GetMethod('ReadResource', $flags))
    $installedRuntime = Join-Path $stagedRoot ('guard-' + ('f' * 64))
    [void][IO.Directory]::CreateDirectory($installedRuntime)
    foreach ($name in $guardFiles) { Copy-Item -LiteralPath (Join-Path $payload $name) -Destination $installedRuntime }
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $owner = 'S-1-5-21-1-2-3-1001'
    function Test-TaskMigration([string]$Directory, [string]$TaskOwner = $owner, [string]$Enabled = 'true', [string]$TriggerEnabled = 'true') {
        $Directory = [Security.SecurityElement]::Escape($Directory)
        $xml = @"
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Principals><Principal><UserId>$TaskOwner</UserId></Principal></Principals>
<Triggers><LogonTrigger><Enabled>$TriggerEnabled</Enabled></LogonTrigger></Triggers>
<Settings><Enabled>$Enabled</Enabled></Settings>
<Actions><Exec><Command>$powershell</Command><WorkingDirectory>$Directory</WorkingDirectory>
<Arguments>-NoProfile -File "$Directory\gpt_vpn_guard_watch.ps1"</Arguments></Exec></Actions>
</Task>
"@
        return $needsMigration.Invoke($xml, $stagedRoot, $owner, 'PC\test', $resource)
    }
    $legacyRuntime = Join-Path $case 'Legacy runtime'
    if (-not (Test-TaskMigration $legacyRuntime) -or (Test-TaskMigration $installedRuntime) -or
        (Test-TaskMigration $legacyRuntime -Enabled 'false') -or (Test-TaskMigration $legacyRuntime -TriggerEnabled 'false') -or
        (Test-TaskMigration $legacyRuntime -TaskOwner 'S-1-5-21-1-2-3-1002')) { throw 'Incorrect decision on startup guard migration.' }
    [IO.File]::AppendAllText((Join-Path $installedRuntime 'gpt_vpn_guard_watch.ps1'), '# older watcher')
    if (-not (Test-TaskMigration $installedRuntime)) { throw 'An outdated protected watcher was missed.' }
    $env:LOCALAPPDATA = Join-Path $case 'Test Local Application Data'
    $data = Join-Path $env:LOCALAPPDATA 'VPN_WORK'
    [void][IO.Directory]::CreateDirectory($data)
    $userBypass = Join-Path $data 'bypass_domains.txt'
    Set-Content -LiteralPath $userBypass -Value 'journal.example.net' -Encoding UTF8
    $split = Join-Path $payload 'split_tunnel.ps1'
    $result = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $split -Packaged -CheckConfig) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $result -notmatch [regex]::Escape($userBypass) -or $result -notmatch '1 host\(s\)') {
        throw "Packaged bypass configuration was not loaded: $result"
    }
    $localGuard = Join-Path $data 'gpt_vpn_guard.local.json'
    @{ Programs = @((Join-Path ([Environment]::SystemDirectory) 'notepad.exe')) } | ConvertTo-Json |
        Set-Content -LiteralPath $localGuard -Encoding UTF8
    $guard = Join-Path $payload 'gpt_vpn_guard.ps1'
    $result = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $guard -Packaged -BlockAll -Plan) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $result -notmatch 'Additional executable: .*notepad\.exe') {
        throw "Packaged guard configuration was not loaded: $result"
    }

    [IO.File]::AppendAllText($split, "`r`n# altered")
    $rejected = $false
    try { [void]$stage.Invoke($stagedRoot) } catch {
        $rejected = $_.Exception.GetBaseException() -is [IO.IOException]
    }
    if (-not $rejected) { throw 'A modified installed script was accepted.' }
    Write-Host 'PASS: standalone EXE, menu actions, guard migration detection, update preference and release validation, local configs, altered payload rejection'
} finally {
    $env:LOCALAPPDATA = $originalData
    if (Test-Path -LiteralPath $case) { Remove-Item -LiteralPath $case -Recurse -Force }
}
