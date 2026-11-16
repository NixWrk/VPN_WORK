param([int]$ParentPid, [string]$Executable, [string]$Pending, [string]$Digest)

$ErrorActionPreference = 'Stop'
$parent = Get-Process -Id $ParentPid -ErrorAction SilentlyContinue
if ($parent) { Wait-Process -InputObject $parent -Timeout 15 -ErrorAction SilentlyContinue }
if ($parent -and -not $parent.HasExited) {
    Remove-Item -LiteralPath $Pending -Force -ErrorAction SilentlyContinue
    exit 1
}

$backup = $Pending + '.bak'
$backupNeeded = $false
try {
    if ((Get-FileHash -LiteralPath $Pending -Algorithm SHA256).Hash -ne $Digest) { throw 'Update changed on disk.' }
    $installed = [Reflection.AssemblyName]::GetAssemblyName($Executable).Version
    $candidate = [Reflection.AssemblyName]::GetAssemblyName($Pending).Version
    if ($candidate -le $installed) { throw 'A newer or equal version is already installed.' }
    [IO.File]::Replace($Pending, $Executable, $backup)
    $backupNeeded = $true
    Start-Process -FilePath $Executable -ArgumentList '--no-update' -WindowStyle Normal
    $backupNeeded = $false
} catch {
    if ($backupNeeded) {
        [IO.File]::Replace($backup, $Executable, [NullString]::Value)
        $backupNeeded = $false
    }
    Start-Process -FilePath $Executable -ArgumentList '--update-failed' -WindowStyle Normal -ErrorAction SilentlyContinue
    exit 1
} finally {
    if (-not $backupNeeded) { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $Pending -Force -ErrorAction SilentlyContinue
}
