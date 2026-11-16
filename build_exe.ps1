[CmdletBinding()]
param([string]$OutputPath)

$ErrorActionPreference = 'Stop'
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot 'dist\VPN_WORK.exe' }
$compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw 'The 64-bit .NET Framework compiler was not found. Build on 64-bit Windows 10/11 with .NET Framework 4.x.'
}

$output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($output))
$temporary = Join-Path ([IO.Path]::GetDirectoryName($output)) ('.vpnwork-' + [guid]::NewGuid().ToString('N') + '.exe')
$items = @('split_tunnel.ps1', 'gpt_vpn_guard.ps1', 'gpt_vpn_filter.cs', 'zotero_proxy.ps1')
$resourceArguments = @($items | ForEach-Object { '/resource:' + (Join-Path $PSScriptRoot $_) + ',' + $_ })
try {
    & $compiler /nologo /target:exe /platform:anycpu /optimize+ /warnaserror+ /codepage:65001 `
        "/out:$temporary" @resourceArguments (Join-Path $PSScriptRoot 'launcher\Program.cs')
    if ($LASTEXITCODE) { throw "C# compilation failed (exit code $LASTEXITCODE)." }
    [IO.File]::Copy($temporary, $output, $true)
    Write-Host "Built $output"
} finally {
    if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
}
