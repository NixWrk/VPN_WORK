# Parse real user files without changing network settings or opening a window.
$ErrorActionPreference = "Stop"
$source = Join-Path (Split-Path $PSScriptRoot -Parent) "split_tunnel.ps1"
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in @("Read-BypassConfig", "Open-BypassConfig", "Test-MonitorIpv4")) {
    $definition = $ast.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true) | Select-Object -First 1
    . ([scriptblock]::Create($definition.Extent.Text))
}
$casePath = Join-Path $PSScriptRoot ("config-" + [guid]::NewGuid().ToString("N"))
try {
    New-Item -ItemType Directory -Path $casePath | Out-Null
    $ConfigFile = Join-Path $casePath "bypass_domains.txt"
    $empty = Read-BypassConfig
    if ($empty.Domains.Count -or $empty.Suffixes.Count -or $empty.Prefixes.Count) { throw "Missing config was not empty" }
    @'
# Comments and blanks are ignored.

https://WWW.NCBI.NLM.NIH.GOV/books/NBK10944/?a=b#part
www.ncbi.nlm.nih.gov
*.Example.ORG
.example.org.
.ru
203.0.113.7
https://203.0.113.7:8448/path
203.0.113.0/24
wss://matrix.example.net:8448/_matrix/client
'@ | Set-Content -LiteralPath $ConfigFile -Encoding UTF8
    $config = Read-BypassConfig
    if (($config.Domains -join ',') -ne 'www.ncbi.nlm.nih.gov,example.org,matrix.example.net' -or
        ($config.Suffixes -join ',') -ne '.example.org,.ru' -or
        ($config.Prefixes -join ',') -ne '203.0.113.7/32,203.0.113.0/24') { throw "Config normalization failed" }
    $idn = [string][char]0x0440 + [string][char]0x0444
    Set-Content -LiteralPath $ConfigFile -Value ('.' + $idn) -Encoding UTF8
    if ((Read-BypassConfig).Suffixes[0] -ne '.xn--p1ai') { throw "IDN suffix was not converted to punycode" }
    foreach ($bad in @('bad host.org', 'example..org', '*.example.org/path', 'file:///C:/example',
        'https://user:password@example.org', '203.0.113.7/24', '203.0.113.0/33', '999.1.2.3',
        '0.0.0.0/0', '127.0.0.1', '2001:db8::1', 'localhost', 'example.org;Get-Process')) {
        Set-Content -LiteralPath $ConfigFile -Value @('# header', $bad) -Encoding UTF8
        $message = ''
        try { Read-BypassConfig | Out-Null } catch { $message = $_.Exception.Message }
        if ($message -notlike '*line 2:*') { throw "Invalid entry accepted or line number missing: $bad" }
    }
    function Start-Process {
        [CmdletBinding()] param($FilePath, $ArgumentList)
        if ($FilePath -ne 'notepad.exe' -or $ArgumentList -ne ('"' + $ConfigFile + '"')) { throw "Wrong editor arguments" }
    }
    Remove-Item -LiteralPath $ConfigFile
    Open-BypassConfig
    $created = [IO.File]::ReadAllText($ConfigFile)
    if ((Read-BypassConfig).Domains.Count -or $created -notmatch 'run_all.cmd') { throw "New editor file was not an empty documented template" }
    Open-BypassConfig
    if ([IO.File]::ReadAllText($ConfigFile) -ne $created) { throw "Editor overwrote an existing config" }
    Copy-Item -LiteralPath $source -Destination $casePath
    $copy = Join-Path $casePath 'split_tunnel.ps1'
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $copy -CheckConfig 2>&1
    if ($LASTEXITCODE -ne 0) { throw "CheckConfig failed: $output" }
    Set-Content -LiteralPath $ConfigFile -Value @('https://chatgpt.com/codex', '*.oaiusercontent.com') -Encoding UTF8
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $copy -CheckConfig 2>&1
    if ($LASTEXITCODE -ne 1 -or ($output -join '') -notmatch 'VPN-only names') { throw "Protected domains accepted in bypass: $output" }
    Set-Content -LiteralPath $ConfigFile -Value 'invalid address' -Encoding UTF8
    $output = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $copy 2>&1
    if ($LASTEXITCODE -ne 1 -or ($output -join '') -notmatch 'line 1:' -or
        ($output -join '') -match 'Requesting Administrator') { throw "Malformed config reached network setup: $output" }
    Write-Host 'PASS: URLs, domains, zones, IDN, IPv4 networks, line errors, native editor and validation before UAC'
} finally {
    $absolute = [IO.Path]::GetFullPath($casePath)
    if (-not $absolute.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Temporary path escaped tests directory'
    }
    if (Test-Path -LiteralPath $absolute) { Remove-Item -LiteralPath $absolute -Recurse -Force }
}
