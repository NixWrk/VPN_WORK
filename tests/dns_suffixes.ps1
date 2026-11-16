# Load only DNS selection functions; never execute the network configuration.
$ErrorActionPreference = "Stop"
$source = Join-Path (Split-Path $PSScriptRoot -Parent) "split_tunnel.ps1"
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
foreach ($name in @("Test-DomainUnderSuffix", "Test-VpnOnlyDomain", "Test-MonitoredDomain", "Test-MonitorIpv4", "ConvertTo-CacheDnsName", "Get-MonitoredCacheCandidates", "Find-CachedDomainsForSuffixes")) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "Missing function $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$exact = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
[void]$exact.Add("yougile.com")
$zones = @('.ru', '.xn--p1ai')
$idn = [Globalization.IdnMapping]::new()
$unicodeHost = $idn.GetUnicode('xn--e1afmkfd.xn--p1ai').ToUpperInvariant() + '.'
$unicodeAlias = $idn.GetUnicode('xn--d1abbgf6aiiy.xn--p1ai').ToUpperInvariant() + '.'
$entries = @(
    # Deliberately reverse the chain: the final address is under a foreign CDN.
    [pscustomobject]@{ Entry = "edge.cdn.example"; Name = "edge.cdn.example"; Type = 1; Data = "203.0.113.10" },
    [pscustomobject]@{ Entry = "first.cdn.example"; Name = "first.cdn.example"; Type = 5; Data = "edge.cdn.example" },
    [pscustomobject]@{ Entry = "shop.ru"; Name = "shop.ru"; Type = 5; Data = "first.cdn.example." },
    [pscustomobject]@{ Entry = "WWW.SHOP.RU."; Type = "A"; Data = "203.0.113.11" },
    [pscustomobject]@{ Entry = "yougile.com"; Type = 1; Data = "203.0.113.12" },
    [pscustomobject]@{ Entry = "rustdesk.com"; Type = 1; Data = "203.0.113.13" },
    [pscustomobject]@{ Entry = "shop.ru.example"; Type = 1; Data = "203.0.113.14" },
    [pscustomobject]@{ Entry = "loop.ru"; Type = 5; Data = "loop.cdn.example" },
    [pscustomobject]@{ Entry = "loop.cdn.example"; Type = 5; Data = "loop.ru" },
    [pscustomobject]@{ Entry = "ipv6.ru"; Type = 28; Data = "2001:db8::1" },
    [pscustomobject]@{ Entry = 'xn--e1afmkfd.xn--p1ai'; Type = 1; Data = '203.0.113.15' },
    [pscustomobject]@{ Entry = $unicodeHost; Type = 1; Data = '203.0.113.16' },
    [pscustomobject]@{ Entry = $unicodeAlias; Type = 5; Data = 'edge.idn.example' },
    [pscustomobject]@{ Entry = 'edge.idn.example.'; Type = 1; Data = '203.0.113.17' },
    [pscustomobject]@{ Entry = 'xn--e1afmkfd.xn--p1ai.example'; Type = 1; Data = '203.0.113.18' }
)
$selected = Get-MonitoredCacheCandidates -Entries $entries -ExactDomains $exact -Suffixes $zones
if ($selected.Count -ne 6 -or $selected["203.0.113.10"] -ne "shop.ru" -or
    $selected["203.0.113.11"] -ne "www.shop.ru" -or $selected["203.0.113.12"] -ne "yougile.com" -or
    $selected['203.0.113.15'] -ne 'xn--e1afmkfd.xn--p1ai' -or $selected['203.0.113.16'] -ne 'xn--e1afmkfd.xn--p1ai' -or
    $selected['203.0.113.17'] -ne 'xn--d1abbgf6aiiy.xn--p1ai') {
    throw 'DNS selection lost a .ru or .xn--p1ai address or included an unrelated name'
}
function Get-DnsClientCache { [CmdletBinding()] param(); return $entries }
$cached = @(Find-CachedDomainsForSuffixes -Suffixes $zones)
if ("shop.ru" -notin $cached -or "www.shop.ru" -notin $cached -or "rustdesk.com" -in $cached -or
    'xn--e1afmkfd.xn--p1ai' -notin $cached -or 'xn--d1abbgf6aiiy.xn--p1ai' -notin $cached) {
    throw "Initial discovery did not include managed CNAME names"
}
$many = @(1..200 | ForEach-Object {
    [pscustomobject]@{ Entry = "host$_.ru"; Type = 1; Data = "198.51.100.$_" }
    [pscustomobject]@{ Entry = "host$_.xn--p1ai"; Type = 1; Data = "192.0.2.$_" }
})
$selected = Get-MonitoredCacheCandidates -Entries $many -ExactDomains $exact -Suffixes $zones
if ($selected.Count -ne 400) { throw 'Managed .ru or .xn--p1ai addresses were truncated' }
foreach ($domain in @('openai.com', 'api.openai.com', 'chatgpt.com', 'files.oaiusercontent.com')) { [void]$exact.Add($domain) }
$protected = @(
    [pscustomobject]@{ Entry = 'API.OpenAI.com.'; Type = 1; Data = '203.0.113.20' },
    [pscustomobject]@{ Entry = 'chatgpt.com'; Type = 1; Data = '203.0.113.21' },
    [pscustomobject]@{ Entry = 'openai.com.ru'; Type = 5; Data = 'files.oaiusercontent.com' },
    [pscustomobject]@{ Entry = 'files.oaiusercontent.com'; Type = 1; Data = '203.0.113.22' },
    [pscustomobject]@{ Entry = 'otheropenai.com'; Type = 1; Data = '203.0.113.23' }
)
$selected = Get-MonitoredCacheCandidates -Entries $protected -ExactDomains $exact -Suffixes @('.com', '.ru')
if ($selected.Count -ne 1 -or $selected['203.0.113.23'] -ne 'otheropenai.com') {
    throw 'OpenAI destination leaked into bypass via exact name, broad suffix, or CNAME'
}
Write-Host 'PASS: .ru and .xn--p1ai, Unicode DNS entries, CNAME routing, suffix boundaries and 400 addresses'
