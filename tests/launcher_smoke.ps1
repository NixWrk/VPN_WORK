# Run a copy of the launcher with harmless scripts: the Zotero step must still
# execute after the split-tunnel step fails.
$ErrorActionPreference = "Stop"
$caseRoot = Join-Path $PSScriptRoot ("launcher-" + [guid]::NewGuid().ToString("N"))
$testsRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$casePath = [IO.Path]::GetFullPath($caseRoot)
if (-not $casePath.StartsWith(
    $testsRoot + [IO.Path]::DirectorySeparatorChar,
    [StringComparison]::OrdinalIgnoreCase
)) { throw "Temporary test path is outside the tests directory" }

try {
    New-Item -ItemType Directory -Path $casePath | Out-Null
    $launcher = Join-Path $casePath "run_all.cmd"
    $marker = Join-Path $casePath "zotero-ran.txt"
    Copy-Item -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) "run_all.cmd") -Destination $launcher
    Set-Content -LiteralPath (Join-Path $casePath "split_tunnel.ps1") -Value "exit 7"
    $escapedMarker = $marker.Replace("'", "''")
    Set-Content -LiteralPath (Join-Path $casePath "zotero_proxy.ps1") `
        -Value "Set-Content -LiteralPath '$escapedMarker' -Value 'ran'; exit 0"

    $command = 'echo. | call "' + $launcher + '"'
    $output = & cmd.exe /d /c $command 2>&1
    if ($LASTEXITCODE -ne 7) { throw "Launcher returned $LASTEXITCODE instead of 7: $output" }
    if (-not (Test-Path -LiteralPath $marker)) { throw "Zotero step was skipped after split-tunnel failure" }
    Write-Host "PASS: launcher reports split-tunnel failure and still runs Zotero"
} finally {
    if (Test-Path -LiteralPath $casePath) {
        Remove-Item -LiteralPath $casePath -Recurse -Force
    }
}
