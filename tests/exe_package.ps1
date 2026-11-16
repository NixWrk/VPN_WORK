# Build and open the one-file package, then stage it in an isolated directory.
# No UAC, scheduled tasks, real configs or network state are changed.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$case = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ('Package check ' + [guid]::NewGuid().ToString('N'))))
if (-not $case.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary packaging path escaped the tests directory.'
}
$originalData = $env:LOCALAPPDATA
$components = @('split_tunnel.ps1', 'gpt_vpn_guard.ps1', 'gpt_vpn_filter.cs', 'zotero_proxy.ps1')
try {
    $build = Join-Path $case 'Build sources'
    [void][IO.Directory]::CreateDirectory((Join-Path $build 'launcher'))
    foreach ($name in ($components + 'build_exe.ps1')) {
        Copy-Item -LiteralPath (Join-Path $root $name) -Destination $build
    }
    Copy-Item -LiteralPath (Join-Path $root 'launcher\Program.cs') -Destination (Join-Path $build 'launcher')
    $exe = Join-Path $case 'Standalone copy\VPN_WORK.exe'
    foreach ($attempt in 1..2) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $build 'build_exe.ps1') -OutputPath $exe
        if ($LASTEXITCODE) { throw "Build attempt $attempt failed." }
    }
    if (@(Get-ChildItem -LiteralPath (Split-Path $exe) -Force).Count -ne 1) { throw 'Distribution requires extra files.' }
    $lines = @(& $exe --verify)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -ne 5) { throw "Package verification failed: $lines" }
    foreach ($name in $components) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        if ("$name $hash" -notin $lines) { throw "Wrong embedded data: $name" }
    }
    $menu = ('0' | & $exe) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $menu -notmatch 'ChatGPT' -or $menu -notmatch 'Zotero') { throw 'Standalone menu failed.' }

    $assembly = [Reflection.Assembly]::Load([IO.File]::ReadAllBytes($exe))
    $install = $assembly.GetType('Program').GetMethod('Install', [Reflection.BindingFlags]'NonPublic,Static')
    $stage = [Delegate]::CreateDelegate([Func[string,string]], $install)
    $stagedRoot = Join-Path $case 'Test Program Files\VPN_WORK'
    [void][IO.Directory]::CreateDirectory((Split-Path $stagedRoot))
    $payload = $stage.Invoke($stagedRoot)
    if ($payload -ne $stage.Invoke($stagedRoot)) { throw 'Staging is not idempotent.' }
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
    Write-Host 'PASS: standalone EXE, reproducible payloads, build paths with spaces, local configs and altered payload rejection'
} finally {
    $env:LOCALAPPDATA = $originalData
    if (Test-Path -LiteralPath $case) { Remove-Item -LiteralPath $case -Recurse -Force }
}
