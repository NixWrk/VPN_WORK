$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$case = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ('proxy-test-' + [guid]::NewGuid().ToString('N') + '.exe')))
if (-not $case.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Temporary proxy test path escaped the tests directory.'
}
$compiler = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
try {
    & $compiler /nologo /warnaserror+ /codepage:65001 /reference:System.Management.dll "/out:$case" `
        (Join-Path $PSScriptRoot 'BrowserProxyTests.cs') (Join-Path $root 'launcher\BrowserProxy.cs') (Join-Path $root 'launcher\BrowserLan.cs')
    if ($LASTEXITCODE) { throw 'Browser proxy regression fixture did not compile.' }
    & $case
    if ($LASTEXITCODE) { throw 'Browser proxy regression fixture failed.' }
} finally {
    if (Test-Path -LiteralPath $case) { Remove-Item -LiteralPath $case -Force }
}
