# Exercise the real replacement helper using two harmless dummy Windows executables.
$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path $PSScriptRoot -Parent
$case = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ("Update check " + [guid]::NewGuid().ToString('N'))))
if (-not $case.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary update path escaped the tests directory.'
}
try {
    [void][IO.Directory]::CreateDirectory($case)
    $compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $executable = Join-Path $case 'VPN WORK.exe'
    $pending = Join-Path $case '.vpnwork-update-test.exe'
    $source = Join-Path $case 'Stub.cs'
    $marker = Join-Path $case 'restart.txt'
    $helper = Join-Path $sourceRoot 'launcher\InstallUpdate.ps1'
    foreach ($minor in 1, 2) {
        $code = @"
[assembly:System.Reflection.AssemblyVersion("1.$minor.0.0")]
static class Stub {
    static void Main(string[] args) {
        if (args.Length == 1 && args[0] == "old-process") { System.Threading.Thread.Sleep(1200); return; }
        var directory = System.AppDomain.CurrentDomain.BaseDirectory;
        System.IO.File.WriteAllText(System.IO.Path.Combine(directory, "restart.txt"), "$minor|" + string.Join(" ", args));
    }
}
"@
        [IO.File]::WriteAllText($source, $code)
        $target = if ($minor -eq 1) { $executable } else { $pending }
        & $compiler /nologo /target:winexe "/out:$target" $source
        if ($LASTEXITCODE) { throw 'Could not compile dummy executable.' }
    }
    function Wait-Restart($Expected) {
        $deadline = [DateTime]::UtcNow.AddSeconds(5)
        do {
            if ((Test-Path -LiteralPath $marker) -and [IO.File]::ReadAllText($marker) -eq $Expected) { return }
            Start-Sleep -Milliseconds 150
        } while ([DateTime]::UtcNow -lt $deadline)
        throw "Unexpected or missing restart marker: $Expected"
    }

    $downloadedDigest = (Get-FileHash -LiteralPath $pending).Hash
    $candidate = [IO.File]::ReadAllBytes($pending)
    $old = Start-Process -FilePath $executable -ArgumentList 'old-process' -PassThru -WindowStyle Hidden
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $helper -ParentPid $old.Id -Executable $executable -Pending $pending -Digest ('0' * 64)
    if ($LASTEXITCODE -ne 1 -or [Reflection.AssemblyName]::GetAssemblyName($executable).Version.Minor -ne 1) {
        throw 'An update with the wrong SHA-256 replaced the executable.'
    }
    Wait-Restart '1|--update-failed'
    [IO.File]::WriteAllBytes($pending, $candidate)
    $old = Start-Process -FilePath $executable -ArgumentList 'old-process' -PassThru -WindowStyle Hidden
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $helper -ParentPid $old.Id -Executable $executable -Pending $pending -Digest $downloadedDigest
    if ($LASTEXITCODE -ne 0 -or (Get-FileHash -LiteralPath $executable).Hash -ne $downloadedDigest) {
        throw 'The verified executable was not installed.'
    }
    Wait-Restart '2|--no-update'
    if ((Test-Path -LiteralPath $pending) -or (Test-Path -LiteralPath ($pending + '.bak'))) {
        throw 'Update files were not cleaned up.'
    }
    Write-Host 'PASS: real Windows replacement waits for exit, rejects tampered bytes, and restarts the correct executable'
} finally {
    if (Test-Path -LiteralPath $case) { Remove-Item -LiteralPath $case -Recurse -Force }
}
