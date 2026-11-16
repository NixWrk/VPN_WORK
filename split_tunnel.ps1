<#
.SYNOPSIS
Настраивает обход VPN для рабочих сервисов, NCBI/PubMed, Element/Matrix, зон .ru и .рф и пользовательских адресов.

.DESCRIPTION
Один переносимый PowerShell-файл без внешних зависимостей. Скрипт сам запрашивает
права администратора, определяет физический Wi-Fi/LAN-шлюз, выбирает рабочий путь
DNS, разрешает актуальные IPv4 сервисов, создаёт проверенные /32-маршруты и
условные DNS-правила NRPT. Фоновая задача отслеживает DNS-кэш и смену адресов,
добавляя новые маршруты без повторного ручного запуска.

Хост WebDAV, настроенный в Zotero, определяется автоматически из prefs.js профиля
Zotero; дополнительные адреса задаются в массиве $ZoteroWebDavUrls. Свои сайты,
зоны и IPv4-сети можно добавить в bypass_domains.txt через -EditConfig.
Element использует стандартные узлы, локальные конфиги и обнаружение публичных
IPv4 его TCP-соединений на каждом ПК.

Зоны .ru и .рф входят в $BypassDomainSuffixes. /32-маршруты создаются для хостов из
$BypassSeedDomains (включая .gost.ru, .bmstu.ru, .gov.ru) и для всех хостов зоны,
найденных в DNS-кэше Windows. Windows не умеет маршрутизировать по имени, поэтому
сайт зоны, открытый впервые, может отправить первый запрос через VPN; фоновый
монитор увидит адрес в DNS-кэше не позднее чем через несколько секунд, после
чего повторный запрос пойдёт напрямую.

Решение рассчитано на Windows 10/11, IPv4 и обычные route-based VPN. VPN с
kill switch/WFP-фильтрацией, корпоративные GPO/NRPT, собственный DoH приложения
или IPv6-only endpoint могут потребовать другого способа обхода.

.PARAMETER Remove
Удаляет маршруты, фоновую задачу и NRPT-правила, ранее созданные этим скриптом.

.PARAMETER Help
Показывает встроенную справку без запроса прав администратора.

.PARAMETER Diagnose
Показывает текущее состояние сети, DNS и фонового монитора без изменения настроек.

.PARAMETER Plan
Показывает предварительный план обновления без изменения настроек.

.PARAMETER EditConfig
Открывает пользовательский список адресов bypass_domains.txt в Блокноте без UAC.
После сохранения запустите скрипт без параметров, чтобы применить изменения.

.PARAMETER CheckConfig
Проверяет пользовательский список адресов без UAC и изменения настроек сети.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\split_tunnel.ps1

Настроить или обновить split tunnel. Монитор отслеживает смену сети и DNS.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\split_tunnel.ps1 -Remove

Удалить управляемые настройки.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\split_tunnel.ps1 -Diagnose

Проверить сеть, DNS и монитор без изменения настроек.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\split_tunnel.ps1 -Plan

Показать предварительный объём обновления без изменения настроек.

.EXAMPLE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\split_tunnel.ps1 -Help

Показать эту инструкцию.

.NOTES
Основное и динамическое состояние хранится в %LOCALAPPDATA% в файлах
split_tunnel_state.json и split_tunnel_monitor_state.json. После первого
успешного запуска перезапустите обслуживаемые приложения. Задача
SplitTunnelRouteMonitor автоматически обновляет маршруты при смене IP; пока
решение установлено, не переносите этот файл без повторной установки задачи.
#>

[CmdletBinding()]
param(
    [switch]$Remove,
    [switch]$Diagnose,
    [switch]$Plan,
    [switch]$EditConfig,
    [switch]$CheckConfig,
    [Parameter(DontShow = $true)]
    [switch]$Packaged,
    [Parameter(DontShow = $true)]
    [switch]$Worker,
    [Alias("h", "?")]
    [switch]$Help
)

# Split-tunnel helper for Windows - pure PowerShell, no external dependencies.
#
# It resolves the current IPv4 addresses used by selected desktop apps and
# adds /32 routes through the real LAN/Wi-Fi gateway. DNS is handled
# independently: the script first verifies public DNS through the physical LAN
# and only falls back to the current route (possibly the VPN) when direct DNS is
# unavailable.
#
# This is portable across ordinary route-based VPN clients, but it is not a
# universal bypass. A VPN kill switch/WFP filter, application-owned DoH,
# IPv6-only endpoints, or a corporate policy can override Windows routes/NRPT.
#
# Requires Windows. This file requests Administrator privileges automatically.

$PublicDnsServers = @("8.8.8.8", "1.1.1.1")
$DnsProbeName = "example.com"
$DnsCriticalNames = @("yougile.com", "yandex.ru")
$NationalBypassSuffixes = @(".ru", ".xn--p1ai")
$BypassZoneProbeNames = @("yandex.ru", "xn--90aivcdt6dxbc.xn--p1ai") # объясняем.рф
$SystemDnsProbeNames = $BypassZoneProbeNames + @("yougile.com", "pubmed.ncbi.nlm.nih.gov", "matrix-client.matrix.org")
$NrptComment = "split_tunnel managed rule"
$script:NrptTouched = $false
$script:PreviousManagedNrptRules = @()
$RouteMetric = 5
$StateFile = Join-Path $env:LOCALAPPDATA "split_tunnel_state.json"
$MonitorStateFile = Join-Path $env:LOCALAPPDATA "split_tunnel_monitor_state.json"
$MonitorLogFile = Join-Path $env:LOCALAPPDATA "split_tunnel_monitor.log"
$ApplyLogFile = Join-Path $env:LOCALAPPDATA "split_tunnel_apply.log"
$MonitorTaskName = "SplitTunnelRouteMonitor"
$MonitorPollSeconds = 3
$MonitorResolveSeconds = 30
$MonitorDnsCheckSeconds = 20
$MonitorDnsFailureThreshold = 3
$MonitorRouteRetentionHours = 24
$configDirectory = if ($Packaged) { Join-Path $env:LOCALAPPDATA 'VPN_WORK' } else { $PSScriptRoot }
$ConfigFile = Join-Path $configDirectory "bypass_domains.txt"

# Some services return content-node IPs directly in API responses, so those
# addresses never appear in the Windows DNS cache. Keep narrowly scoped,
# provider-owned networks here; they are installed persistently and are removed
# by -Remove together with the ordinary per-host routes.
$StaticBypassPrefixes = [ordered]@{
    "Cloud Mail / Disk-O content nodes" = @("95.163.51.0/24")
}

# Exact host names of additional sites that must bypass the VPN.
# This is required for sites built on 1C-Bitrix or hosted on a custom domain:
# the CMS/hosting platform cannot be determined from the route table.
# Enter host names without paths. URLs with https:// are also accepted.
$CustomSiteDomains = @(
    # "example.ru"
    # "www.example.ru"
    # "company.bitrix24.ru"
)

# Domain suffixes that must bypass the VPN as a whole zone.
# Windows routes packets by address and never by name, so a suffix is applied
# in two steps:
#   * one NRPT rule per suffix resolves every name below it through the
#     verified resolver - this part really does cover the whole zone;
#   * every host below the suffix gets its own /32 route, but only once the
#     host is known: from $BypassSeedDomains, or from the Windows DNS cache,
#     which lists what this machine has actually opened.
# A host visited for the first time can send its first request through the VPN;
# the background monitor discovers it in the DNS cache within a few seconds and
# moves subsequent attempts to the direct path.
# Non-ASCII suffixes must be written in punycode (".xn--p1ai" for ".рф").
$BypassDomainSuffixes = $NationalBypassSuffixes + @(
    ".vk.com", ".vkuser.net", ".vkuseraudio.net",
    ".userapi.com", ".vk-cdn.net"
)

# Hosts below $BypassDomainSuffixes that are routed on the very first run,
# before this machine has ever opened them. The ".gost.ru", ".bmstu.ru" and
# ".gov.ru" sites are listed by name because they reject foreign VPN addresses
# outright, so their bypass must not depend on cache discovery.
$BypassSeedDomains = @(
    "gost.ru", "www.gost.ru", "protect.gost.ru",
    "bmstu.ru", "www.bmstu.ru", "uchsov.bmstu.ru", "mf.bmstu.ru",
    "lks.bmstu.ru", "e-learning.bmstu.ru", "library.bmstu.ru",
    "gov.ru", "www.gov.ru", "rospatent.gov.ru",
    "fips.ru", "new.fips.ru",
    "consultant.ru", "www.consultant.ru",
    "static.consultant.ru", "login.consultant.ru"
    "ozon.ru", "www.ozon.ru", "st.ozone.ru", "io.ozone.ru",
    "ir-20.ozone.ru", "v-1.ozone.ru"
    "xn--90aivcdt6dxbc.xn--p1ai" # объясняем.рф
)

# WebDAV storage used by Zotero for attachment sync.
# Every Zotero profile listed in profiles.ini has its own WebDAV endpoint, and
# all of them are detected automatically - including profiles stored outside
# %APPDATA% on another drive. Addresses listed here are added on top of whatever
# is detected, which covers a profile that is not registered yet or a host that
# Zotero has not verified. Paths are ignored: only the host name is routed.
$ZoteroWebDavUrls = @()

$VpnHints = @(
    "wireguard", "openvpn", "tap-windows", "tap windows", "wintun",
    "vpn", "tunnel", "ppp", "zerotier", "nordlynx", "cisco anyconnect",
    "forticlient", "globalprotect", "ikev2", "wan miniport",
    "red shield", "redshield"
)

$Apps = [ordered]@{
    "YouGile" = @(
        "yougile.com", "ru.yougile.com", "api.yougile.com",
        "data.yougile.com", "dist.yougile.com", "analytics.yougile.com"
    )
    "Pachca" = @(
        "pachca.com", "api.pachca.com", "app.pachca.com", "wss.pachca.com",
        "app-1.pachca.ru", "meet.pachca.com", "site-cdn.pachca.com",
        "489609.selcdn.ru", "pachca-prod-uploads.s3.storage.selcloud.ru",
        "api.todesktop.com", "download.todesktop.com",
        "us-central1-todesktop-prod1.cloudfunctions.net"
    )
    "Cloud Mail / Disk-O" = @(
        "cloud.mail.ru", "api.disk-o.cloud", "dispatcher.cloud.mail.ru",
        "disk-o.cloud", "disko.cloud.mail.ru",
        "cloud-diskoshar.q.smailru.net",
        "auth.mail.ru", "l-clients.cloud.mail.ru",
        "uploader.cloud.mail.ru", "webdav.cloud.mail.ru",
        "wlapi.cloud.mail.ru", "disko-api.cloud.mail.ru",
        "profile.cloud.mail.ru", "e.mail.ru", "oauth.mail.ru",
        "hb.bizmrg.com", "jdcloud.mail.ru", "cloud.radar.imgsmail.ru",
        "cld-extapi.datacloudmail.ru", "cld-extapi.q.smailru.net",
        "o2.mail.ru"
    )
    "VK" = @(
        "vk.com", "m.vk.com", "api.vk.com", "id.vk.com", "oauth.vk.com",
        "vk.ru", "id.vk.ru", "api.vk.ru", "vkvideo.ru",
        "vkuser.net", "vkuseraudio.net", "userapi.com"
    )
    "Zotero cloud" = @(
        "zotero.org", "www.zotero.org", "api.zotero.org",
        "download.zotero.org"
    )
    "NCBI / PubMed" = @(
        "ncbi.nlm.nih.gov", "www.ncbi.nlm.nih.gov", "pubmed.ncbi.nlm.nih.gov",
        "pmc.ncbi.nlm.nih.gov", "cdn.ncbi.nlm.nih.gov", "eutils.ncbi.nlm.nih.gov"
    )
    # Public defaults; local homeservers are detected separately on each PC.
    # Sources: Element's published network requirements and matrix.org's
    # /.well-known/matrix/client (including its current MatrixRTC service).
    "Element / Matrix" = @(
        "element.io", "www.element.io", "app.element.io", "packages.element.io",
        "matrix.org", "matrix-client.matrix.org", "vector.im", "scalar.vector.im",
        "call.element.io", "call.ems.host", "livekit-jwt.call.element.io",
        "sfu.call.element.io", "livekit-jwt.call.matrix.org",
        "integrations.element.io", "integrations.ems.host", "meet.element.io",
        "stun.l.google.com", "stun1.l.google.com"
    )
    "Yandex services" = @(
        "yandex.ru", "ya.ru", "yandex.com", "yandex.net", "yastatic.net",
        "passport.yandex.ru", "oauth.yandex.ru", "mc.yandex.ru",
        "api-maps.yandex.ru", "maps.yandex.ru", "captcha-api.yandex.ru",
        "smartcaptcha.yandexcloud.net", "avatars.mds.yandex.net",
        "mail.yandex.ru",
        "calendar.yandex.ru", "docs.yandex.ru", "telemost.yandex.ru",
        "api.messenger.yandex.net",
        "files.messenger.yandex.net", "stun.rtc.yandex.net",
        "turn.webrtc.yandex.net", "translate.yandex.net"
    )
    # Yandex's published network requirements list separate API, transfer and
    # WebDAV hosts. Storage shards are discovered from the Windows DNS cache.
    "Yandex Disk" = @(
        "disk.yandex.ru", "disk.360.yandex.ru", "disk.yandex.net",
        "cloud-api.yandex.net", "api.disk.yandex.net", "api.disk.yandex.ru",
        "dataapi.disk.yandex.net", "intapi.disk.yandex.net",
        "webdav.yandex.ru", "webdav.disk.yandex.net", "webdav.disk.yandex.ru",
        "uploader.disk.yandex.net",
        "downloader.disk.yandex.ru", "downloader.disk.yandex.net",
        "front.disk.yandex.ru", "www.disk.yandex.ru",
        "streaming.disk.yandex.net", "zipper-external.disk.yandex.net"
    )
    "Bitrix24 cloud" = @(
        "bitrix24.ru", "www.bitrix24.ru", "bitrix24.com", "www.bitrix24.com",
        "bitrix24.net", "auth2.bitrix24.net", "oauth.bitrix.info",
        "dl.bitrix24.com", "repos.1c-bitrix.ru", "www.1c-bitrix.ru",
        "bitrix24site.ru", "bitrix24shop.ru", "b24site.online", "b24shop.online"
    )
}

$NrptNamespaces = @(
    ".yougile.com", ".yougile.ru",
    ".pachca.com", ".pachca.ru", ".selcloud.ru", ".selcdn.ru",
    ".todesktop.com", "us-central1-todesktop-prod1.cloudfunctions.net",
    ".mail.ru", ".disk-o.cloud", ".bizmrg.com", ".imgsmail.ru",
    ".smailru.net",
    ".zotero.org",
    ".ncbi.nlm.nih.gov",
    ".element.io", ".matrix.org", ".vector.im", ".ems.host", ".modular.im", ".riot.im",
    ".yandex.ru", ".yandex.com", ".yandex.net", ".ya.ru", ".yastatic.net",
    ".yandexcloud.net",
    ".bitrix24.ru", ".bitrix24.com", ".bitrix24.net", ".bitrix.info", ".1c-bitrix.ru",
    ".bitrix24site.ru", ".bitrix24shop.ru", ".b24site.online", ".b24shop.online"
)



function ConvertTo-DomainName {
    param([Parameter(Mandatory = $true)][string]$Value)

    $candidate = $Value.Trim()
    if (-not $candidate) { return $null }

    try {
        if ($candidate -notmatch '^[a-z][a-z0-9+.-]*://') {
            $candidate = "https://$candidate"
        }
        $uri = [uri]$candidate
        if (-not $uri.Host) { return $null }
        return $uri.IdnHost.TrimEnd('.').ToLowerInvariant()
    } catch {
        Write-Host "WARNING: invalid custom site address is skipped: $Value"
        return $null
    }
}

function ConvertTo-DomainList {
    param([string[]]$Values)

    $domains = @(
        foreach ($value in @($Values)) {
            if (-not $value) { continue }
            $domain = ConvertTo-DomainName -Value ([string]$value)
            if ($domain) { $domain }
        }
    )
    return @($domains | Select-Object -Unique)
}

function ConvertTo-DomainSuffix {
    param([Parameter(Mandatory = $true)][string]$Value)

    $candidate = $Value.Trim().TrimEnd('.').ToLowerInvariant()
    if (-not $candidate) { return $null }
    if ($candidate.StartsWith("*.")) { $candidate = $candidate.Substring(1) }
    if (-not $candidate.StartsWith(".")) { $candidate = ".$candidate" }
    if ($candidate -notmatch '^(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$') {
        Write-Host "WARNING: invalid domain suffix is skipped: $Value"
        return $null
    }
    return $candidate
}

function ConvertTo-SuffixList {
    param([string[]]$Values)

    $suffixes = @(
        foreach ($value in @($Values)) {
            if (-not $value) { continue }
            $suffix = ConvertTo-DomainSuffix -Value ([string]$value)
            if ($suffix) { $suffix }
        }
    )
    return @($suffixes | Select-Object -Unique)
}

function Read-BypassConfig {
    param([string]$Path = $ConfigFile)

    $domains = @()
    $suffixes = @()
    $prefixes = @()
    if (Test-Path -LiteralPath $Path) {
        $lineNumber = 0
        foreach ($line in [IO.File]::ReadAllLines($Path, [Text.Encoding]::UTF8)) {
            $lineNumber++
            $value = $line.Trim()
            if (-not $value -or $value.StartsWith("#")) { continue }
            try {
                if ($value -match '^\d+\.\d+\.\d+\.\d+(?:/\d+)?$') {
                    $parts = $value -split '/'
                    $address = $null
                    if (-not [Net.IPAddress]::TryParse($parts[0], [ref]$address) -or
                        -not (Test-MonitorIpv4 -Value $parts[0])) { throw "invalid IPv4 address" }
                    $length = if ($parts.Count -eq 2) { [int]$parts[1] } else { 32 }
                    if ($length -lt 1 -or $length -gt 32) { throw "IPv4 prefix length must be 1..32" }
                    $bytes = $address.GetAddressBytes()
                    for ($i = 0; $i -lt 4; $i++) {
                        $bits = [Math]::Max(0, [Math]::Min(8, $length - 8 * $i))
                        $mask = if ($bits) { [int](256 - [Math]::Pow(2, 8 - $bits)) } else { 0 }
                        if (($bytes[$i] -band $mask) -ne $bytes[$i]) { throw "use the network address for CIDR" }
                    }
                    $prefixes += "$($address.IPAddressToString)/$length"
                    continue
                }
                $isSuffix = $value.StartsWith(".") -or $value.StartsWith("*.")
                if ($isSuffix) {
                    $hostName = $value.TrimStart('*', '.').TrimEnd('.')
                    $hostName = [Globalization.IdnMapping]::new().GetAscii($hostName).ToLowerInvariant()
                } else {
                    $uriValue = if ($value -match '^[a-z][a-z0-9+.-]*://') { $value } else { "https://$value" }
                    $uri = [uri]$uriValue
                    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -notin @("https", "http", "wss", "ws") -or
                        $uri.UserInfo) { throw "use a hostname or an HTTP(S)/WS(S) URL without credentials" }
                    $hostName = $uri.IdnHost.TrimEnd('.').ToLowerInvariant()
                    if ([uri]::CheckHostName($hostName) -eq [UriHostNameType]::IPv4) {
                        if (-not (Test-MonitorIpv4 -Value $hostName)) { throw "invalid IPv4 destination" }
                        $prefixes += "$hostName/32"
                        continue
                    }
                }
                if ($hostName.Length -gt 253 -or $hostName -notmatch '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$' -or
                    [uri]::CheckHostName($hostName) -ne [UriHostNameType]::Dns) { throw "invalid DNS hostname" }
                foreach ($label in ($hostName -split '\.')) {
                    if ($label.Length -gt 63 -or $label -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$') {
                        throw "invalid DNS label"
                    }
                }
                if (-not $hostName.Contains(".") -and -not $isSuffix) { throw "use a full DNS hostname" }
                if ($isSuffix) { $suffixes += ".$hostName" }
                if ($hostName.Contains(".")) { $domains += $hostName }
            } catch {
                throw "${Path}: line ${lineNumber}: $($_.Exception.Message)"
            }
        }
    }
    return [PSCustomObject]@{
        Domains = @($domains | Select-Object -Unique)
        Suffixes = @($suffixes | Select-Object -Unique)
        Prefixes = @($prefixes | Select-Object -Unique)
    }
}

function Open-BypassConfig {
    if (-not (Test-Path -LiteralPath $ConfigFile)) {
        [void][IO.Directory]::CreateDirectory((Split-Path -LiteralPath $ConfigFile))
        $template = @'
# Дополнительные адреса для обхода VPN. Одна запись на строку; # — комментарий.
# Сайт: journal.example.org или https://journal.example.org/article/123
# Сайт вместе со всеми поддоменами: .example.org или *.example.org
# IP или сеть IPv4: 203.0.113.10 или 203.0.113.0/24
# Примеры выше закомментированы. Добавьте свои адреса ниже.
# После сохранения примените обход через VPN_WORK.exe или запустите run_all.cmd.
# Встроенные сервисы (включая NCBI/PubMed и Element) уже обслуживаются.
'@
        [IO.File]::WriteAllText($ConfigFile, $template + "`r`n", [Text.UTF8Encoding]::new($true))
    }
    Start-Process -FilePath "notepad.exe" -ArgumentList "`"$ConfigFile`"" -ErrorAction Stop | Out-Null
    Write-Host "Config: $ConfigFile"
    Write-Host "Save the file, then apply routes in VPN_WORK.exe or run split_tunnel.ps1."
}

function Test-DomainUnderSuffix {
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [string[]]$Suffixes
    )

    foreach ($suffix in @($Suffixes)) {
        if (-not $suffix) { continue }
        if ($Domain.EndsWith($suffix, [System.StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

function Test-VpnOnlyDomain {
    param([string]$Domain)

    $name = $Domain.Trim().Trim('.').ToLowerInvariant()
    # OpenAI service zones from its network recommendations. Enforcement is by application in
    # gpt_vpn_guard; this is only a safeguard against conflicting bypass routes.
    return $name -match '(^|\.)(openai\.com|chatgpt\.com|oaistatic\.com|oaiusercontent\.com|oaistatsig\.com|openaimerge\.com)$'
}

function ConvertTo-CacheDnsName([string]$Value) {
    $name = $Value.Trim().TrimEnd('.').ToLowerInvariant()
    if ($name -match '[^\x00-\x7F]') {
        try { return [Globalization.IdnMapping]::new().GetAscii($name) } catch { return '' }
    }
    return $name
}

function Find-CachedDomainsForSuffixes {
    param([string[]]$Suffixes)

    # A /32 route can only be created for a host that is already known by name,
    # so a whole-zone suffix has to be turned into concrete hosts on every run.
    # The DNS client cache is that source: it holds exactly the names this
    # machine has really looked up. Only the queried name is taken from the
    # cache - the address is resolved again through the verified resolver.
    if (@($Suffixes).Count -eq 0) { return @() }

    $entries = Get-DnsClientCache -ErrorAction SilentlyContinue
    if (-not $entries) { return @() }

    $domains = @()
    foreach ($entry in $entries) {
        $recordType = [string]$entry.Type
        if ($recordType -notin @("1", "A", "5", "CNAME")) { continue }

        $name = ConvertTo-CacheDnsName ([string]$entry.Entry)
        if (-not $name -or (Test-VpnOnlyDomain $name)) { continue }
        if (-not (Test-DomainUnderSuffix -Domain $name -Suffixes $Suffixes)) { continue }
        $domains += $name
    }
    return @($domains | Select-Object -Unique | Sort-Object)
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Find-NextcloudDomain {
    $cfg = Join-Path $env:APPDATA "Nextcloud\nextcloud.cfg"
    if (-not (Test-Path -LiteralPath $cfg)) { return $null }
    $content = Get-Content -LiteralPath $cfg -Raw -ErrorAction SilentlyContinue
    if (-not $content) { return $null }
    foreach ($match in [regex]::Matches($content, 'url=(https?://[^\s]+)', 'IgnoreCase')) {
        try {
            $uri = [uri]$match.Groups[1].Value
            if ($uri.Host) { return $uri.Host }
        } catch {}
    }
    return $null
}

function Find-ElementDomains {
    # Read only user-specified JSON configuration, never account databases,
    # access tokens, encryption keys or message history.
    $paths = @()
    foreach ($directory in @(Get-ChildItem -LiteralPath $env:APPDATA -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '^(Element|ElementNightly|Riot)(-.+)?$' })) {
        $paths += Join-Path $directory.FullName "config.json"
    }
    if ($env:ELEMENT_DESKTOP_CONFIG_JSON) { $paths += $env:ELEMENT_DESKTOP_CONFIG_JSON }
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $processes = @(Get-CimInstance Win32_Process -Filter "Name = 'Element.exe' OR Name = 'ElementNightly.exe' OR Name = 'element-desktop.exe' OR Name = 'Riot.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $sessionId })
    foreach ($process in $processes) {
        foreach ($option in @("config", "profile-dir")) {
            $pattern = '(?:^|\s)--' + $option + '(?:=|\s+)(?:"([^"]+)"|(\S+))'
            $match = [regex]::Match([string]$process.CommandLine, $pattern, 'IgnoreCase')
            if (-not $match.Success) { continue }
            $path = if ($match.Groups[1].Success) { $match.Groups[1].Value } else { $match.Groups[2].Value }
            # Relative paths belong to the application's working directory.
            if (-not [IO.Path]::IsPathRooted($path)) { continue }
            if ($option -eq "profile-dir") { $path = Join-Path $path "config.json" }
            $paths += $path
        }
    }
    $domains = @()
    foreach ($path in @($paths | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        try {
            $config = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $values = @(
                $config.default_server_name, $config.default_hs_url, $config.default_is_url,
                $config.default_server_config.'m.homeserver'.base_url,
                $config.default_server_config.'m.identity_server'.base_url,
                $config.integrations_ui_url, $config.integrations_rest_url,
                $config.element_call.url, $config.jitsi.preferred_domain
            )
            foreach ($focus in @($config.'org.matrix.msc4143.rtc_foci')) {
                if ($focus.livekit_service_url) { $values += $focus.livekit_service_url }
            }
            $domains += @(ConvertTo-DomainList -Values $values)
        } catch {
            Write-Host "WARNING: could not read an Element config; active connections will still be detected."
        }
    }
    return @($domains | Select-Object -Unique)
}

function Get-ElementRemoteAddresses {
    # Connection discovery also works when the account's homeserver exists
    # only in encrypted/LevelDB storage or the app uses its own DNS resolver.
    $sessionId = [Diagnostics.Process]::GetCurrentProcess().SessionId
    $processIds = @(Get-Process -Name "Element", "ElementNightly", "element-desktop", "Riot" -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $sessionId } | ForEach-Object { $_.Id })
    if ($processIds.Count -eq 0) { return @() }
    $addresses = foreach ($connection in @(Get-NetTCPConnection -OwningProcess $processIds `
        -State Established, SynSent -ErrorAction SilentlyContinue)) {
        $ip = [string]$connection.RemoteAddress
        if (-not (Test-MonitorIpv4 -Value $ip)) { continue }
        $bytes = ([Net.IPAddress]$ip).GetAddressBytes()
        # Leave LAN, link-local and private overlay destinations on their
        # existing routes; forcing those through a LAN router can break them.
        if ($bytes[0] -eq 10 -or
            ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) -or
            ($bytes[0] -eq 192 -and $bytes[1] -eq 168) -or
            ($bytes[0] -eq 169 -and $bytes[1] -eq 254) -or
            ($bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127)) { continue }
        $ip
    }
    return @($addresses | Select-Object -Unique)
}

function Get-ZoteroProfileDirectory {
    # Zotero profiles are not necessarily stored under %APPDATA%: profiles.ini
    # may point at any drive, so the ini is the authoritative list and the
    # Profiles folder is only a fallback. The ini is UTF-8 in current builds and
    # ANSI in older ones, and a profile path may contain non-Latin characters,
    # so it is decoded both ways and only paths that really exist are kept.
    $root = Join-Path $env:APPDATA "Zotero\Zotero"
    if (-not (Test-Path -LiteralPath $root)) { return @() }

    $directories = @()
    $ini = Join-Path $root "profiles.ini"
    if (Test-Path -LiteralPath $ini) {
        $decoders = @([System.Text.Encoding]::UTF8, [System.Text.Encoding]::Default)
        foreach ($decoder in $decoders) {
            $content = $null
            try {
                $content = [System.IO.File]::ReadAllText($ini, $decoder)
            } catch {
                continue
            }
            if (-not $content) { continue }

            $sections = @()
            $current = $null
            foreach ($line in ($content -split "\r?\n")) {
                $trimmed = $line.Trim()
                if ($trimmed -match '^\[.*\]$') {
                    if ($current) { $sections += , $current }
                    $current = @{}
                    continue
                }
                if ($null -eq $current) { continue }
                if ($trimmed -match '^([^=]+)=(.*)$') {
                    $current[$Matches[1].Trim()] = $Matches[2].Trim()
                }
            }
            if ($current) { $sections += , $current }

            foreach ($section in $sections) {
                if (-not $section.ContainsKey("Path")) { continue }
                $path = [string]$section["Path"]
                if (-not $path) { continue }

                $isRelative = $true
                if ($section.ContainsKey("IsRelative")) {
                    $isRelative = ([string]$section["IsRelative"] -ne "0")
                }
                if ($isRelative) { $path = Join-Path $root ($path -replace '/', '\') }
                if (Test-Path -LiteralPath $path) { $directories += $path }
            }
        }
    }

    $profilesRoot = Join-Path $root "Profiles"
    if (Test-Path -LiteralPath $profilesRoot) {
        $directories += @(
            Get-ChildItem -LiteralPath $profilesRoot -Directory -ErrorAction SilentlyContinue |
                ForEach-Object { $_.FullName }
        )
    }

    return @($directories | Select-Object -Unique)
}

function Find-ZoteroWebDavDomains {
    # Zotero keeps the WebDAV target in the profile preferences:
    #   extensions.zotero.sync.storage.protocol = "webdav"
    #   extensions.zotero.sync.storage.url      = "host[/path]"  (no scheme)
    # Every profile has its own endpoint, so all of them are inspected.
    $domains = @()
    foreach ($directory in (Get-ZoteroProfileDirectory)) {
        $prefs = Join-Path $directory "prefs.js"
        if (-not (Test-Path -LiteralPath $prefs)) { continue }
        $content = Get-Content -LiteralPath $prefs -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        $protocol = [regex]::Match(
            $content,
            'user_pref\("extensions\.zotero\.sync\.storage\.protocol",\s*"([^"]*)"\s*\)'
        )
        if ($protocol.Success -and $protocol.Groups[1].Value -ne "webdav") { continue }

        $url = [regex]::Match(
            $content,
            'user_pref\("extensions\.zotero\.sync\.storage\.url",\s*"([^"]*)"\s*\)'
        )
        if (-not $url.Success -or -not $url.Groups[1].Value) { continue }

        $domain = ConvertTo-DomainName -Value $url.Groups[1].Value
        if ($domain) { $domains += $domain }
    }
    return @($domains | Select-Object -Unique)
}

function Find-YouGileShardDomains {
    $networkState = Join-Path $env:APPDATA "YouGile\Network\Network Persistent State"
    if (-not (Test-Path -LiteralPath $networkState)) { return @() }
    $content = Get-Content -LiteralPath $networkState -Raw -ErrorAction SilentlyContinue
    if (-not $content) { return @() }
    return @(
        [regex]::Matches($content, '(?i)\b(?:an\d+-acc\d+)\.yougile\.com\b') |
            ForEach-Object { $_.Value.ToLowerInvariant() } |
            Select-Object -Unique
    )
}

function Find-Bitrix24DesktopDomains {
    # The desktop client records the active portal in tabs2.txt. Service hosts
    # such as auth2 and the regional RTC shard are discovered from its own log
    # and from the Windows DNS cache, because those names can change over time.
    $root = Join-Path $env:APPDATA "Bitrix\Desktop\3.0"
    if (-not (Test-Path -LiteralPath $root)) { return @() }

    $serviceSuffixes = @(
        ".bitrix24.ru", ".bitrix24.com", ".bitrix24.net", ".bitrix.info",
        ".bitrix24site.ru", ".bitrix24shop.ru", ".b24site.online", ".b24shop.online"
    )
    $escapedServiceSuffixes = @(
        $serviceSuffixes | ForEach-Object { [regex]::Escape($_.TrimStart([char]'.')) }
    )
    $serviceUrlPattern = (
        '(?i)https?://((?:[a-z0-9-]+\.)*(?:' +
        ($escapedServiceSuffixes -join '|') +
        '))(?=[:/]|$)'
    )
    $domains = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    $tabs = Join-Path $root "tabs2.txt"
    if (Test-Path -LiteralPath $tabs) {
        $content = Get-Content -LiteralPath $tabs -Raw -ErrorAction SilentlyContinue
        foreach ($match in [regex]::Matches([string]$content, '(?i)https?://([a-z0-9.-]+)')) {
            $domain = ConvertTo-DomainName -Value $match.Value
            if ($domain) { [void]$domains.Add($domain) }
        }
    }

    # Bitrix logs can grow to hundreds of megabytes. Only recent entries are
    # relevant, so inspect at most 128 KiB from each of the two most recent logs.
    $recentLogs = @(
        Get-ChildItem -LiteralPath $root -Filter "bitrix24*.log" -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 2
    )
    $maxLogBytes = 128KB
    foreach ($log in $recentLogs) {
        $stream = $null
        try {
            $stream = [IO.File]::Open(
                $log.FullName,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::ReadWrite
            )
            $count = [int][Math]::Min($maxLogBytes, $stream.Length)
            [void]$stream.Seek(-$count, [IO.SeekOrigin]::End)
            $buffer = [byte[]]::new($count)
            $read = 0
            while ($read -lt $count) {
                $chunk = $stream.Read($buffer, $read, $count - $read)
                if ($chunk -le 0) { break }
                $read += $chunk
            }
            # URLs and host names are ASCII even when the surrounding log is not.
            $content = [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        } catch {
            continue
        } finally {
            if ($stream) { $stream.Dispose() }
        }

        foreach ($match in [regex]::Matches($content, $serviceUrlPattern)) {
            [void]$domains.Add($match.Groups[1].Value.ToLowerInvariant())
        }
    }

    foreach ($entry in @(Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        $recordType = [string]$entry.Type
        if ($recordType -ne "1" -and $recordType -ne "A") { continue }
        $domain = ([string]$entry.Entry).Trim().TrimEnd('.').ToLowerInvariant()
        if ($domain -and (Test-DomainUnderSuffix -Domain $domain -Suffixes $serviceSuffixes)) {
            [void]$domains.Add($domain)
        }
    }

    return @($domains | Sort-Object)
}

function Find-RealGateway {
    $routes = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
    $candidates = @()
    foreach ($route in $routes) {
        $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
        if (-not $adapter -or $adapter.Status -ne "Up") { continue }
        if (-not $adapter.HardwareInterface -or $route.NextHop -eq "0.0.0.0") { continue }

        $description = $adapter.InterfaceDescription.ToLowerInvariant()
        $isVpn = $false
        foreach ($hint in $VpnHints) {
            if ($description -like "*$hint*") {
                $isVpn = $true
                break
            }
        }
        if ($isVpn) { continue }

        $ipInterface = Get-NetIPInterface `
            -AddressFamily IPv4 `
            -InterfaceIndex $route.InterfaceIndex `
            -ErrorAction SilentlyContinue
        $interfaceMetric = if ($ipInterface) { $ipInterface.InterfaceMetric } else { 9999 }
        $candidates += [PSCustomObject]@{
            Gateway = $route.NextHop
            IfIndex = $route.InterfaceIndex
            Metric = $route.RouteMetric + $interfaceMetric
            Desc = $adapter.InterfaceDescription
        }
    }

    if ($candidates.Count -eq 0) { return $null }
    return ($candidates | Sort-Object Metric | Select-Object -First 1)
}

function Read-ManagedState {
    if (-not (Test-Path -LiteralPath $StateFile)) { return $null }
    try {
        return (Get-Content -LiteralPath $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        Write-Host "WARNING: state file is unreadable; managed NRPT rules will still be removed."
        return $null
    }
}

function Update-ManagedGateway {
    param(
        [Parameter(Mandatory = $true)]$Configuration,
        [Parameter(Mandatory = $true)]$Gateway
    )

    if ([int]$Configuration.InterfaceIndex -eq [int]$Gateway.IfIndex -and
        [string]$Configuration.Gateway -eq [string]$Gateway.Gateway) {
        return $Configuration
    }

    # Migrate already known prefixes without waiting for DNS. Keep the old
    # state/routes until the new routes and the state file have been prepared.
    $previousRoutes = @($Configuration.Routes | Where-Object { $_.Prefix })
    $activeIndex = @{}
    $adoptableIndex = @{}
    $ownedPrefixes = @{}
    foreach ($record in $previousRoutes) { $ownedPrefixes[[string]$record.Prefix] = $true }
    foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)) {
        $identity = Get-RouteIdentity -Prefix $route.DestinationPrefix `
            -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop
        $activeIndex[$identity] = $true
    }
    foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore -ErrorAction Stop)) {
        if ([int]$route.InterfaceIndex -ne [int]$Gateway.IfIndex -or
            [string]$route.NextHop -ne [string]$Gateway.Gateway -or
            [int]$route.RouteMetric -ne $RouteMetric -or
            -not $ownedPrefixes.ContainsKey([string]$route.DestinationPrefix)) { continue }
        $identity = Get-RouteIdentity -Prefix $route.DestinationPrefix `
            -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop
        if ($activeIndex.ContainsKey($identity)) { $adoptableIndex[$identity] = $true }
    }

    $created = @()
    $updatedRoutes = @()
    $temporaryFile = $StateFile + ".tmp"
    try {
        foreach ($record in $previousRoutes) {
            $parts = [string]$record.Prefix -split '/'
            if ($parts.Count -ne 2) { throw "Invalid saved prefix: $($record.Prefix)" }
            $result = Add-PersistentManagedRoute -Ip $parts[0] -PrefixLength ([int]$parts[1]) `
                -Gateway $Gateway -Kind ([string]$record.Kind) `
                -ActiveRouteIndex $activeIndex -AdoptableRouteIndex $adoptableIndex
            if (-not $result.Ok) { throw "Could not migrate $($record.Prefix): $($result.Message)" }
            if ($result.Created) { $created += $result.Record }
            if ($result.Record) {
                if ($record.LastSeen) { $result.Record.LastSeen = [string]$record.LastSeen }
                if ($record.PSObject.Properties.Name -contains "Domains") {
                    $result.Record | Add-Member -NotePropertyName Domains -NotePropertyValue @($record.Domains)
                }
                $updatedRoutes += $result.Record
            }
        }
        $latestGateway = Find-RealGateway
        if (-not $latestGateway -or $latestGateway.IfIndex -ne $Gateway.IfIndex -or
            $latestGateway.Gateway -ne $Gateway.Gateway) {
            throw "LAN gateway changed while routes were being migrated"
        }

        $updated = [ordered]@{}
        foreach ($property in $Configuration.PSObject.Properties) {
            $updated[$property.Name] = $property.Value
        }
        $updated.InterfaceIndex = [int]$Gateway.IfIndex
        $updated.Gateway = [string]$Gateway.Gateway
        $updated.InterfaceDescription = [string]$Gateway.Desc
        $updated.UpdatedAt = (Get-Date).ToUniversalTime().ToString("o")
        $updated.Routes = @($updatedRoutes)
        $updated | ConvertTo-Json -Depth 6 -ErrorAction Stop |
            Set-Content -LiteralPath $temporaryFile -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $temporaryFile -Destination $StateFile -Force -ErrorAction Stop
    } catch {
        Remove-RouteRecords -Records $created
        Remove-Item -LiteralPath $temporaryFile -Force -ErrorAction SilentlyContinue
        throw
    }
    Remove-RouteRecords -Records @($previousRoutes | Where-Object {
        [int]$_.InterfaceIndex -ne [int]$Gateway.IfIndex -or
        [string]$_.NextHop -ne [string]$Gateway.Gateway
    })
    Write-MonitorLog "Updated LAN gateway/index: $($Configuration.Gateway)/$($Configuration.InterfaceIndex) -> $($Gateway.Gateway)/$($Gateway.IfIndex)."
    return [PSCustomObject]$updated
}

function Set-MonitorRouteGateway {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)]$Gateway
    )

    # Preserve the address, original host and retention timestamp. The worker
    # will restore this route on the current interface in its ordinary loop.
    if ([int]$Record.InterfaceIndex -ne [int]$Gateway.IfIndex -or
        [string]$Record.NextHop -ne [string]$Gateway.Gateway) {
        Remove-MonitorRouteRecord -Record $Record
    }
    return [PSCustomObject]@{
        Prefix = [string]$Record.Prefix
        InterfaceIndex = [int]$Gateway.IfIndex
        NextHop = [string]$Gateway.Gateway
        Metric = $RouteMetric
        Kind = if ($Record.Kind -eq "Element") { "Element" } else { "Monitor" }
        Domain = [string]$Record.Domain
        LastSeen = [string]$Record.LastSeen
    }
}

function Remove-RouteRecord($record) {
    if (-not $record) { return }
    $prefix = [string]$record.Prefix
    $nextHop = [string]$record.NextHop
    $ifIndex = [int]$record.InterfaceIndex
    $metric = [int]$record.Metric
    if (-not $prefix -or -not $nextHop -or $ifIndex -le 0) { return }

    foreach ($store in @("ActiveStore", "PersistentStore")) {
        $routes = Get-NetRoute `
            -DestinationPrefix $prefix `
            -InterfaceIndex $ifIndex `
            -PolicyStore $store `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $nextHop -and $_.RouteMetric -eq $metric }
        foreach ($route in @($routes)) {
            $route | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Remove-RouteRecords {
    param(
        $Records,
        [hashtable]$ActiveRouteObjectIndex = $null,
        [hashtable]$PersistentRouteObjectIndex = $null
    )

    $recordList = @($Records | Where-Object { $_ })
    if (
        $null -eq $ActiveRouteObjectIndex -and
        $null -eq $PersistentRouteObjectIndex -and
        $recordList.Count -gt 4
    ) {
        $targetKeys = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($record in $recordList) {
            [void]$targetKeys.Add(
                "$($record.Prefix)|$($record.InterfaceIndex)|$($record.NextHop)|$($record.Metric)"
            )
        }
        foreach ($store in @("ActiveStore", "PersistentStore")) {
            foreach ($route in @(
                Get-NetRoute `
                    -AddressFamily IPv4 `
                    -PolicyStore $store `
                    -ErrorAction SilentlyContinue
            )) {
                $key = "$($route.DestinationPrefix)|$($route.InterfaceIndex)|$($route.NextHop)|$($route.RouteMetric)"
                if ($targetKeys.Contains($key)) {
                    $route | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
        }
        return
    }

    foreach ($record in $recordList) {
        if (-not $record) { continue }
        $prefix = [string]$record.Prefix
        $nextHop = [string]$record.NextHop
        $ifIndex = [int]$record.InterfaceIndex
        $metric = [int]$record.Metric
        if (-not $prefix -or -not $nextHop -or $ifIndex -le 0) { continue }
        $identity = "$prefix|$ifIndex|$nextHop|$metric"
        if ($null -ne $ActiveRouteObjectIndex -and $null -ne $PersistentRouteObjectIndex) {
            foreach ($route in @($ActiveRouteObjectIndex[$identity])) {
                if ($route) {
                    $route | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
            foreach ($route in @($PersistentRouteObjectIndex[$identity])) {
                if ($route) {
                    $route | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
            continue
        }

        foreach ($store in @("ActiveStore", "PersistentStore")) {
            Remove-NetRoute `
                -DestinationPrefix $prefix `
                -InterfaceIndex $ifIndex `
                -NextHop $nextHop `
                -RouteMetric $metric `
                -PolicyStore $store `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
        }
    }
}
function Remove-LegacyRoute($prefix) {
    if (-not $prefix) { return }
    $candidates = @(
        Get-NetRoute `
            -DestinationPrefix ([string]$prefix) `
            -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.RouteMetric -eq $RouteMetric -and $_.Protocol -eq "NetMgmt"
            }
    )
    if ($candidates.Count -ne 1) {
        Write-Host "WARNING: legacy route $prefix was not removed: expected one managed candidate, found $($candidates.Count)."
        return
    }

    $candidate = $candidates[0]
    Remove-RouteRecord ([PSCustomObject]@{
        Prefix = [string]$candidate.DestinationPrefix
        InterfaceIndex = [int]$candidate.InterfaceIndex
        NextHop = [string]$candidate.NextHop
        Metric = [int]$candidate.RouteMetric
    })
}

function Remove-ManagedNrptRules($ruleNames) {
    $rules = Get-DnsClientNrptRule -ErrorAction SilentlyContinue
    if (@($ruleNames).Count -gt 0) {
        $rules = $rules | Where-Object { $_.Name -in @($ruleNames) }
    } else {
        $rules = $rules | Where-Object { $_.Comment -eq $NrptComment }
    }
    $rules | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
}

function Remove-PreviousManagedState {
    $state = Read-ManagedState
    $savedNrptRuleNames = @()
    if ($state) {
        $hasVersion = $state.PSObject.Properties.Name -contains "Version"
        if ($hasVersion -and [int]$state.Version -ge 2) {
            Remove-RouteRecords @($state.Routes)
            $savedNrptRuleNames = @($state.NrptRuleNames)
        } else {
            foreach ($prefix in @($state)) { Remove-LegacyRoute $prefix }
        }
    }
    Remove-ManagedNrptRules $savedNrptRuleNames
    Remove-Item -LiteralPath $StateFile -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

function Test-DnsServer {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [string]$Name = $DnsProbeName,
        [switch]$TcpOnly,
        [switch]$SkipCacheClear
    )

    if (-not $SkipCacheClear) { Clear-DnsClientCache -ErrorAction SilentlyContinue }
    $arguments = @{
        Name = $Name
        Type = "A"
        Server = $Server
        DnsOnly = $true
        NoHostsFile = $true
        QuickTimeout = $true
        ErrorAction = "Stop"
    }
    if ($TcpOnly) { $arguments.TcpOnly = $true }

    try {
        $answer = Resolve-DnsName @arguments
        return [bool]@($answer | Where-Object { $_.Type -eq "A" -and $_.IPAddress -and (Test-MonitorIpv4 $_.IPAddress) }).Count
    } catch {
        return $false
    }
}

function ConvertFrom-NslookupAnswer {
    param(
        [string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Server
    )

    $ips = @(
        foreach ($match in [regex]::Matches(
            ($Lines -join "`n"),
            '(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])'
        )) {
            [Net.IPAddress]$address = $null
            if (-not [Net.IPAddress]::TryParse($match.Value, [ref]$address)) { continue }
            if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { continue }
            if ($address.IPAddressToString -eq $Server) { continue }
            if (-not (Test-MonitorIpv4 $address.IPAddressToString)) { continue }
            $address.IPAddressToString
        }
    )
    return @($ips | Select-Object -Unique)
}

function Resolve-IpsWithNslookup {
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][string]$Server
    )

    # nslookup.exe sends a direct query to the named server. On some VPNs,
    # Resolve-DnsName -Server still times out for namespaces in the current NRPT.
    try {
        $output = @( & nslookup.exe -type=A -timeout=2 -retry=1 $Domain $Server 2>&1 )
        if ($LASTEXITCODE -ne 0) { return @() }
        return @(ConvertFrom-NslookupAnswer -Lines ([string[]]$output) -Server $Server)
    } catch {
        return @()
    }
}

function Test-DnsCandidate {
    param([Parameter(Mandatory = $true)][string]$Server, [switch]$Report)

    # Resolving example.com alone does not prove that the resolver can serve
    # the domains managed by this script.
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    foreach ($name in @($DnsProbeName) + $DnsCriticalNames) {
        if (-not (Test-DnsServer -Server $Server -Name $name -SkipCacheClear) -and
            @(Resolve-IpsWithNslookup -Domain $name -Server $Server).Count -eq 0) {
            if ($Report) { Write-Host "  [DNS] $server -> $name [NO USABLE IPv4 ANSWER]" }
            return $false
        }
    }
    return $true
}

function Test-EffectiveManagedDns {
    return (@(Resolve-Ips -Domain "yandex.ru" -DnsServers @()).Count -gt 0)
}

function Test-DnsViaNrpt {
    param([Parameter(Mandatory = $true)][string]$Server, [switch]$Report)

    # An explicit -Server lookup can succeed while Windows blocks that resolver
    # for NRPT. Probe the actual system resolution path before choosing it.
    $probeRule = $null
    try {
        $probeRule = Add-DnsClientNrptRule `
            -Namespace $DnsProbeName `
            -NameServers $Server `
            -Comment "split_tunnel temporary DNS probe" `
            -DisplayName "split_tunnel temporary DNS probe" `
            -PassThru `
            -ErrorAction Stop
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        $answer = Resolve-DnsName `
            -Name $DnsProbeName `
            -Type A `
            -DnsOnly `
            -NoHostsFile `
            -QuickTimeout `
            -ErrorAction Stop
        if (@($answer | Where-Object { $_.Type -eq "A" -and $_.IPAddress -and (Test-MonitorIpv4 $_.IPAddress) }).Count -gt 0) { return $true }
        if ($Report) { Write-Host "  [NRPT probe] $server [NO USABLE IPv4 ANSWER]" }
        return $false
    } catch {
        if ($Report) { Write-Host "  [NRPT probe] $server [FAILED: $($_.Exception.Message)]" }
        return $false
    } finally {
        if ($probeRule) {
            $probeRule | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
        }
        Clear-DnsClientCache -ErrorAction SilentlyContinue
    }
}

function Resolve-Ips {
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$DnsServers
    )

    $allIps = @()
    $servers = @($DnsServers)
    if ($servers.Count -eq 0) { $servers = @('') } # Use the Windows DNS client without forcing a server.
    foreach ($server in $servers) {
        $params = @{ Name = $Domain; Type = 'A'; DnsOnly = $true; NoHostsFile = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
        if ($server) { $params.Server = $server }
        $answer = try { Resolve-DnsName @params } catch { @() }
        $ips = @(
            $answer |
                Where-Object { $_.Type -eq "A" -and $_.IPAddress -and (Test-MonitorIpv4 $_.IPAddress) } |
                Select-Object -ExpandProperty IPAddress -Unique
        )
        if ($ips.Count -eq 0 -and $server) {
            $ips = @(Resolve-IpsWithNslookup -Domain $Domain -Server $server)
        }
        $allIps += $ips
    }
    return @($allIps | Select-Object -Unique)
}

function Resolve-DomainMap {
    param(
        [Parameter(Mandatory = $true)][string[]]$Domains,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$DnsServers,
        [ValidateRange(1, 32)][int]$Throttle = 12
    )

    $uniqueDomains = @($Domains | Where-Object { $_ } | Select-Object -Unique)
    $domainMap = @{}
    if ($uniqueDomains.Count -eq 0) { return ,$domainMap }

    $pool = $null
    $jobs = @()
    try {
        $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $sessionState.ImportPSModule(@("DnsClient"))
        foreach ($functionName in @("Test-MonitorIpv4", "ConvertFrom-NslookupAnswer", "Resolve-IpsWithNslookup", "Resolve-Ips")) {
            $definition = (Get-Command $functionName -CommandType Function).Definition
            $sessionState.Commands.Add(
                [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new(
                    $functionName, $definition
                )
            )
        }
        $pool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle, $sessionState, $Host)
        $pool.Open()

        $worker = {
            param($Domain, $Servers)

            [PSCustomObject]@{ Ips = @(Resolve-Ips -Domain $Domain -DnsServers $Servers) }
        }

        foreach ($domain in $uniqueDomains) {
            $shell = [PowerShell]::Create()
            $shell.RunspacePool = $pool
            [void]$shell.AddScript($worker).AddArgument($domain).AddArgument($DnsServers)
            $jobs += [PSCustomObject]@{
                Domain = $domain
                Shell = $shell
                Handle = $shell.BeginInvoke()
            }
        }

        foreach ($job in $jobs) {
            try {
                $result = $job.Shell.EndInvoke($job.Handle) | Select-Object -Last 1
                if ($null -ne $result) { $domainMap[$job.Domain] = @($result.Ips) }
            } catch {
                # Fall back below if the runspace itself failed.
            }
        }
    } catch {
        # A runspace/module failure must affect speed only, never DNS coverage.
    } finally {
        foreach ($job in $jobs) {
            if ($job.Shell) { $job.Shell.Dispose() }
        }
        if ($pool) {
            $pool.Close()
            $pool.Dispose()
        }
    }

    foreach ($domain in $uniqueDomains) {
        if (-not $domainMap.ContainsKey($domain)) {
            $domainMap[$domain] = @(Resolve-Ips -Domain $domain -DnsServers $DnsServers)
        }
    }
    return ,$domainMap
}

function Test-DnsDirectViaLan {
    param(
        [Parameter(Mandatory = $true)][string]$Server,
        [Parameter(Mandatory = $true)]$Gateway
    )

    # The router itself is already on the connected LAN; a /32 via itself is unnecessary.
    if ($Server -eq $Gateway.Gateway) { return (Test-DnsServer -Server $Server) }

    $prefix = "$Server/32"
    $existing = Get-NetRoute `
        -DestinationPrefix $prefix `
        -InterfaceIndex $Gateway.IfIndex `
        -PolicyStore ActiveStore `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -eq $Gateway.Gateway }
    if ($existing) { return (Test-DnsServer -Server $Server) }

    $temporaryRoute = $null
    try {
        $temporaryRoute = New-NetRoute `
            -DestinationPrefix $prefix `
            -InterfaceIndex $Gateway.IfIndex `
            -NextHop $Gateway.Gateway `
            -RouteMetric $RouteMetric `
            -PolicyStore ActiveStore `
            -ErrorAction Stop
        return (Test-DnsServer -Server $Server)
    } catch {
        return $false
    } finally {
        if ($temporaryRoute) {
            $temporaryRoute | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        }
    }
}

function Get-LanDnsServers {
    param([Parameter(Mandatory = $true)]$Gateway)

    $configured = @(
        Get-DnsClientServerAddress `
            -InterfaceIndex $Gateway.IfIndex `
            -AddressFamily IPv4 `
            -ErrorAction SilentlyContinue |
            ForEach-Object { $_.ServerAddresses }
    )
    return @($configured | Where-Object { $_ -and $_ -ne "0.0.0.0" } | Select-Object -Unique)
}

function Get-CurrentVpnDnsServers {
    # Some VPN clients install many narrower routes rather than a default route.
    # Discover their DNS from active virtual adapters, then prefer servers whose
    # effective route points back to that adapter.
    $candidates = @(
        foreach ($adapter in @(Get-NetAdapter -ErrorAction SilentlyContinue)) {
            if ($adapter.Status -ne "Up" -or $adapter.HardwareInterface) { continue }
            $ipInterface = Get-NetIPInterface `
                -AddressFamily IPv4 `
                -InterfaceIndex $adapter.InterfaceIndex `
                -ErrorAction SilentlyContinue
            $metric = if ($ipInterface) { [int]$ipInterface.InterfaceMetric } else { 9999 }
            $configured = Get-DnsClientServerAddress `
                -InterfaceIndex $adapter.InterfaceIndex `
                -AddressFamily IPv4 `
                -ErrorAction SilentlyContinue
            foreach ($server in @($configured.ServerAddresses | Select-Object -Unique)) {
                [Net.IPAddress]$address = $null
                if (-not [Net.IPAddress]::TryParse([string]$server, [ref]$address)) { continue }
                if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
                    $server -eq "0.0.0.0") { continue }
                $route = @(
                    Find-NetRoute -RemoteIPAddress $server -ErrorAction SilentlyContinue |
                        Where-Object { $_.PSObject.Properties.Name -contains "DestinationPrefix" }
                ) | Select-Object -First 1
                [pscustomobject]@{
                    Server = [string]$server
                    OnAdapter = [bool]($route -and [int]$route.InterfaceIndex -eq [int]$adapter.InterfaceIndex)
                    Metric = $metric
                }
            }
        }
    )
    return @(
        $candidates |
            Sort-Object `
                @{ Expression = "OnAdapter"; Descending = $true },
                @{ Expression = "Metric"; Descending = $false } |
            Select-Object -ExpandProperty Server -Unique
    )
}

function Get-RouteIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Prefix,
        [Parameter(Mandatory = $true)][int]$InterfaceIndex,
        [Parameter(Mandatory = $true)][string]$NextHop
    )

    return "$Prefix|$InterfaceIndex|$NextHop"
}

function Add-PersistentManagedRoute {
    param(
        [Parameter(Mandatory = $true)][string]$Ip,
        [Parameter(Mandatory = $true)]$Gateway,
        [Parameter(Mandatory = $true)][string]$Kind,
        [ValidateRange(0, 32)][int]$PrefixLength = 32,
        [hashtable]$ActiveRouteIndex = $null,
        [hashtable]$AdoptableRouteIndex = $null
    )

    $prefix = "$Ip/$PrefixLength"
    $maskOctets = @(
        for ($octet = 0; $octet -lt 4; $octet++) {
            $remainingBits = $PrefixLength - ($octet * 8)
            $bits = [Math]::Max(0, [Math]::Min(8, $remainingBits))
            if ($bits -eq 0) { 0 }
            else { [int](256 - [Math]::Pow(2, 8 - $bits)) }
        }
    )
    $subnetMask = $maskOctets -join "."
    $routeIdentity = Get-RouteIdentity `
        -Prefix $prefix `
        -InterfaceIndex $Gateway.IfIndex `
        -NextHop $Gateway.Gateway
    $record = [PSCustomObject]@{
        Prefix = $prefix
        InterfaceIndex = [int]$Gateway.IfIndex
        NextHop = [string]$Gateway.Gateway
        Metric = $RouteMetric
        Kind = $Kind
        LastSeen = (Get-Date).ToUniversalTime().ToString("o")
    }
    if ($null -ne $ActiveRouteIndex) {
        $existing = $ActiveRouteIndex.ContainsKey($routeIdentity)
    } else {
        $existing = Get-NetRoute `
            -DestinationPrefix $prefix `
            -InterfaceIndex $Gateway.IfIndex `
            -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $Gateway.Gateway }
    }
    if ($existing) {
        $managedRecord = $null
        if (
            $null -ne $AdoptableRouteIndex -and
            $AdoptableRouteIndex.ContainsKey($routeIdentity)
        ) {
            $managedRecord = $record
        }
        return [PSCustomObject]@{
            Ok = $true
            Created = $false
            Record = $managedRecord
            Message = "already present"
        }
    }

    $output = & route.exe -p add $Ip mask $subnetMask $Gateway.Gateway metric $RouteMetric if $Gateway.IfIndex 2>&1
    if ($LASTEXITCODE -ne 0) {
        return [PSCustomObject]@{
            Ok = $false
            Created = $false
            Record = $null
            Message = (($output | Select-Object -Last 1) -join " ")
        }
    }

    if ($null -ne $ActiveRouteIndex) {
        $ActiveRouteIndex[$routeIdentity] = $true
        if ($null -ne $AdoptableRouteIndex) {
            $AdoptableRouteIndex[$routeIdentity] = $true
        }
    } else {
        $installed = Get-NetRoute `
            -DestinationPrefix $prefix `
            -InterfaceIndex $Gateway.IfIndex `
            -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $Gateway.Gateway -and $_.RouteMetric -eq $RouteMetric }
        if (-not $installed) {
            Remove-RouteRecord $record
            return [PSCustomObject]@{
                Ok = $false
                Created = $false
                Record = $null
                Message = "route verification failed"
            }
        }
    }

    return [PSCustomObject]@{
        Ok = $true
        Created = $true
        Record = $record
        Message = "created"
    }
}
function Add-ManagedNrptRules {
    param(
        [Parameter(Mandatory = $true)][string[]]$Namespaces,
        [Parameter(Mandatory = $true)][string[]]$NameServers
    )

    $ruleNames = @()
    foreach ($namespace in @($Namespaces | Select-Object -Unique)) {
        $rule = Add-DnsClientNrptRule `
            -Namespace $namespace `
            -NameServers $NameServers `
            -Comment $NrptComment `
            -DisplayName "split_tunnel: $namespace" `
            -PassThru `
            -ErrorAction Stop
        $ruleNames += [string]$rule.Name
    }
    return $ruleNames
}

function Sync-ManagedNrptRules {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Namespaces,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$NameServers,
        [string[]]$PreviousRuleNames = @()
    )

    $desiredNamespaces = @($Namespaces | Where-Object { $_ } | Select-Object -Unique)
    $desiredNamespaceSet = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($namespace in $desiredNamespaces) {
        [void]$desiredNamespaceSet.Add($namespace)
    }
    $keptNamespaces = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    $desiredServerKey = (@($NameServers | Sort-Object -Unique) -join "|").ToLowerInvariant()
    $ruleNames = @()

    $managedRules = @(
        Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Comment -eq $NrptComment -or
                [string]$_.Name -in @($PreviousRuleNames)
            }
    )
    foreach ($rule in $managedRules) {
        $ruleNamespaces = @([string[]]$rule.Namespace | Where-Object { $_ })
        $ruleServerKey = (
            @([string[]]$rule.NameServers | Sort-Object -Unique) -join "|"
        ).ToLowerInvariant()
        $keep = (
            $ruleNamespaces.Count -eq 1 -and
            $desiredNamespaceSet.Contains($ruleNamespaces[0]) -and
            $ruleServerKey -eq $desiredServerKey -and
            -not $keptNamespaces.Contains($ruleNamespaces[0])
        )
        if ($keep) {
            [void]$keptNamespaces.Add($ruleNamespaces[0])
            $ruleNames += [string]$rule.Name
        } else {
            $rule | Remove-DnsClientNrptRule -Force -ErrorAction Stop
        }
    }

    foreach ($namespace in $desiredNamespaces) {
        if ($keptNamespaces.Contains($namespace)) { continue }
        $rule = Add-DnsClientNrptRule `
            -Namespace $namespace `
            -NameServers $NameServers `
            -Comment $NrptComment `
            -DisplayName "split_tunnel: $namespace" `
            -PassThru `
            -ErrorAction Stop
        [void]$keptNamespaces.Add($namespace)
        $ruleNames += [string]$rule.Name
    }
    return $ruleNames
}

function Rollback-CurrentRun($routes) {
    Remove-RouteRecords @($routes)
    if ($script:NrptTouched) {
        Remove-ManagedNrptRules @()
        foreach ($savedRule in $script:PreviousManagedNrptRules) {
            try {
                Add-DnsClientNrptRule `
                    -Namespace $savedRule.Namespace `
                    -NameServers $savedRule.NameServers `
                    -Comment $NrptComment `
                    -DisplayName $savedRule.DisplayName `
                    -ErrorAction Stop |
                    Out-Null
            } catch {
                Write-Host "WARNING: could not restore NRPT rule $($savedRule.Namespace): $($_.Exception.Message)"
            }
        }
    }
    Remove-Item -LiteralPath ($StateFile + ".tmp") -Force -ErrorAction SilentlyContinue
    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

function Write-MonitorLog {
    param([Parameter(Mandatory = $true)][string]$Message)

    try {
        if (
            (Test-Path -LiteralPath $MonitorLogFile) -and
            (Get-Item -LiteralPath $MonitorLogFile -ErrorAction Stop).Length -gt 512KB
        ) {
            Set-Content -LiteralPath $MonitorLogFile -Value "" -Encoding UTF8
        }
        Add-Content `
            -LiteralPath $MonitorLogFile `
            -Value "$((Get-Date).ToString('o')) $Message" `
            -Encoding UTF8
    } catch {}
}

function Read-MonitorState {
    if (-not (Test-Path -LiteralPath $MonitorStateFile)) { return $null }
    try {
        return Get-Content -LiteralPath $MonitorStateFile -Raw -Encoding UTF8 |
            ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
}

function Save-MonitorState {
    param([Parameter(Mandatory = $true)][hashtable]$RouteIndex)

    $state = [ordered]@{
        Version = 1
        UpdatedAt = (Get-Date).ToUniversalTime().ToString("o")
        Routes = @($RouteIndex.Values | Sort-Object Prefix)
    }
    $temporaryFile = $MonitorStateFile + ".tmp"
    $state | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $temporaryFile -Encoding UTF8 -ErrorAction Stop
    Move-Item `
        -LiteralPath $temporaryFile `
        -Destination $MonitorStateFile `
        -Force `
        -ErrorAction Stop
}

function Remove-MonitorRouteRecord {
    param([Parameter(Mandatory = $true)]$Record)

    $prefix = [string]$Record.Prefix
    $nextHop = [string]$Record.NextHop
    $ifIndex = [int]$Record.InterfaceIndex
    $metric = [int]$Record.Metric
    if (-not $prefix -or -not $nextHop -or $ifIndex -le 0) { return }

    Get-NetRoute `
        -DestinationPrefix $prefix `
        -InterfaceIndex $ifIndex `
        -PolicyStore ActiveStore `
        -ErrorAction SilentlyContinue |
        Where-Object {
            $_.NextHop -eq $nextHop -and
            [int]$_.RouteMetric -eq $metric
        } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
}

function Remove-RouteMonitorRoutes {
    $monitorState = Read-MonitorState
    foreach ($record in @($monitorState.Routes)) {
        Remove-MonitorRouteRecord -Record $record
    }
    Remove-Item -LiteralPath $MonitorStateFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath ($MonitorStateFile + ".tmp") -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $MonitorLogFile -Force -ErrorAction SilentlyContinue
}

function Stop-RouteMonitorTask {
    param([switch]$Unregister)

    $task = Get-ScheduledTask -TaskName $MonitorTaskName -ErrorAction SilentlyContinue
    if (-not $task) { return }

    Stop-ScheduledTask -TaskName $MonitorTaskName -ErrorAction SilentlyContinue
    foreach ($attempt in 1..20) {
        $task = Get-ScheduledTask -TaskName $MonitorTaskName -ErrorAction SilentlyContinue
        if (-not $task -or [string]$task.State -ne "Running") { break }
        Start-Sleep -Milliseconds 250
    }
    if ($Unregister) {
        Unregister-ScheduledTask `
            -TaskName $MonitorTaskName `
            -Confirm:$false `
            -ErrorAction SilentlyContinue
    }
}

function Register-RouteMonitorTask {
    Stop-RouteMonitorTask -Unregister

    $powerShellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Worker"
    if ($Packaged) { $arguments += ' -Packaged' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $action = New-ScheduledTaskAction -Execute $powerShellExe -Argument $arguments
    $logonTrigger = New-ScheduledTaskTrigger -AtLogOn -User $identity
    $repeatTrigger = New-ScheduledTaskTrigger `
        -Once `
        -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal `
        -UserId $identity `
        -LogonType Interactive `
        -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    Register-ScheduledTask `
        -TaskName $MonitorTaskName `
        -Action $action `
        -Trigger @($logonTrigger, $repeatTrigger) `
        -Principal $principal `
        -Settings $settings `
        -Description "Keeps split-tunnel routes synchronized with rotating DNS addresses" `
        -Force |
        Out-Null
    Start-ScheduledTask -TaskName $MonitorTaskName -ErrorAction Stop
    foreach ($attempt in 1..40) {
        $task = Get-ScheduledTask -TaskName $MonitorTaskName -ErrorAction SilentlyContinue
        if ($task -and [string]$task.State -eq "Running") { return }
        Start-Sleep -Milliseconds 250
    }
    throw "scheduled route monitor did not stay running"
}

function Test-MonitorIpv4 {
    param([Parameter(Mandatory = $true)][string]$Value)

    $address = $null
    if (-not [Net.IPAddress]::TryParse($Value, [ref]$address)) { return $false }
    if ($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $bytes = $address.GetAddressBytes()
    # 198.18.0.0/15 is commonly synthesized by TUN DNS (FakeIP). Its addresses are not direct targets.
    return ($bytes[0] -gt 0 -and $bytes[0] -ne 127 -and $bytes[0] -lt 224 -and
        -not ($bytes[0] -eq 198 -and $bytes[1] -in @(18, 19)))
}

function Test-MonitoredDomain {
    param(
        [Parameter(Mandatory = $true)][string]$Domain,
        [Parameter(Mandatory = $true)]$ExactDomains,
        [string[]]$Suffixes
    )

    $normalized = ConvertTo-CacheDnsName $Domain
    if (-not $normalized -or (Test-VpnOnlyDomain $normalized)) { return $false }
    if ($ExactDomains.Contains($normalized)) { return $true }
    return Test-DomainUnderSuffix -Domain $normalized -Suffixes $Suffixes
}

function Get-MonitoredCacheCandidates {
    param(
        [object[]]$Entries,
        [Parameter(Mandatory = $true)]$ExactDomains,
        [string[]]$Suffixes
    )

    # Keep the original managed name across CNAME chains, even when the final
    # A record is cached under a CDN name outside the bypassed suffix.
    $names = @{}
    foreach ($entry in $Entries) {
        foreach ($value in @($entry.Entry, $entry.Name)) {
            $name = ConvertTo-CacheDnsName ([string]$value)
            if ($name -and (Test-MonitoredDomain -Domain $name -ExactDomains $ExactDomains -Suffixes $Suffixes)) {
                $names[$name] = $name
            }
        }
    }
    do {
        $changed = $false
        foreach ($entry in $Entries) {
            if ([string]$entry.Type -notin @("5", "CNAME")) { continue }
            $target = ConvertTo-CacheDnsName ([string]$entry.Data)
            if (-not $target -or $names.ContainsKey($target) -or (Test-VpnOnlyDomain $target)) { continue }
            foreach ($value in @($entry.Name, $entry.Entry)) {
                $alias = ConvertTo-CacheDnsName ([string]$value)
                if ($names.ContainsKey($alias)) {
                    $names[$target] = $names[$alias]
                    $changed = $true
                    break
                }
            }
        }
    } while ($changed)

    $candidates = @{}
    foreach ($entry in $Entries) {
        if ([string]$entry.Type -notin @("1", "A")) { continue }
        $ip = [string]$entry.Data
        if (-not $ip -or -not (Test-MonitorIpv4 -Value $ip)) { continue }
        foreach ($value in @($entry.Name, $entry.Entry)) {
            $name = ConvertTo-CacheDnsName ([string]$value)
            if ($names.ContainsKey($name)) {
                $candidates[$ip] = $names[$name]
                break
            }
        }
    }
    return ,$candidates
}

function Request-ConfigurationRefresh {
    $powerShellExe = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
    if ($Packaged) { $arguments += ' -Packaged' }
    Start-Process -FilePath $powerShellExe -ArgumentList $arguments -WindowStyle Hidden -ErrorAction Stop | Out-Null
}

function Start-RouteMonitor {
    if (-not (Test-IsAdmin)) {
        Write-MonitorLog "ERROR: monitor is not running with Administrator privileges."
        exit 1
    }

    $configuration = Read-ManagedState
    if (
        -not $configuration -or
        -not ($configuration.PSObject.Properties.Name -contains "MonitorDomains")
    ) {
        Write-MonitorLog "ERROR: monitor configuration is missing; run split_tunnel.ps1 again."
        exit 1
    }

    $gateway = [PSCustomObject]@{
        Gateway = [string]$configuration.Gateway
        IfIndex = [int]$configuration.InterfaceIndex
    }
    if (-not $gateway.Gateway -or $gateway.IfIndex -le 0) {
        Write-MonitorLog "Saved gateway/index is invalid; rediscovering the physical interface."
    }

    # Do not prune dynamic routes against an obsolete interface index. A VPN or
    # Wi-Fi reconnect can renumber interfaces while the saved state is intact.
    $currentGateway = Find-RealGateway
    if (-not $currentGateway) {
        Write-MonitorLog "LAN gateway unavailable at startup; retrying on the next scheduled run."
        exit 0
    }
    if ($currentGateway.IfIndex -ne $gateway.IfIndex -or
        $currentGateway.Gateway -ne $gateway.Gateway) {
        try {
            $configuration = Update-ManagedGateway -Configuration $configuration -Gateway $currentGateway
        } catch {
            Write-MonitorLog "ERROR: could not migrate LAN routes; retrying on the next scheduled run: $($_.Exception.Message)"
            exit 1
        }
    }
    $gateway = $currentGateway

    # Apply built-in host and suffix additions when the scheduled worker starts after
    # the script has been updated but its saved state is still older.
    $builtInDomains = @($Apps.Values | ForEach-Object { $_ } | Select-Object -Unique)
    $savedDomains = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($domain in @($configuration.MonitorDomains)) {
        if ($domain) { [void]$savedDomains.Add([string]$domain) }
    }
    $missingBuiltIns = @($builtInDomains | Where-Object { -not $savedDomains.Contains($_) })
    $monitorSuffixes = @(ConvertTo-SuffixList -Values $configuration.MonitorSuffixes)
    $missingSuffixes = @(ConvertTo-SuffixList -Values $BypassDomainSuffixes | Where-Object { $_ -notin $monitorSuffixes })
    if ($missingBuiltIns.Count -gt 0 -or $missingSuffixes.Count -gt 0) {
        Write-MonitorLog "Saved configuration lacks $($missingBuiltIns.Count) built-in domain(s) or $($missingSuffixes.Count) configured suffix(es); refreshing configuration."
        try { Request-ConfigurationRefresh } catch {
            Write-MonitorLog "ERROR: could not start configuration refresh: $($_.Exception.Message)"
        }
        exit 1
    }
    $knownDomains = @(
        @([string[]]$configuration.MonitorDomains) + $builtInDomains |
            Where-Object { $_ -and -not (Test-VpnOnlyDomain $_) } |
            ForEach-Object { ConvertTo-CacheDnsName $_ } |
            Select-Object -Unique
    )
    $dnsServers = @([string[]]$configuration.DnsServers | Where-Object { $_ })
    $useSystemDns = [string]$configuration.DnsMode -eq "System"
    if ($knownDomains.Count -eq 0 -or (-not $useSystemDns -and $dnsServers.Count -eq 0)) {
        Write-MonitorLog "ERROR: saved domains or DNS servers are empty."
        exit 1
    }

    $exactDomains = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($domain in $knownDomains) { [void]$exactDomains.Add($domain) }

    $trackedRoutes = @{}
    $monitorState = Read-MonitorState
    $configuredPrefixes = @($configuration.Routes | ForEach-Object { $_.Prefix })
    foreach ($record in @($monitorState.Routes)) {
        if (-not $record.Prefix) { continue }
        if ($record.Prefix -like "*/32" -and -not (Test-MonitorIpv4 ($record.Prefix -split '/', 2)[0])) {
            Remove-MonitorRouteRecord -Record $record
            continue
        }
        # A re-apply can adopt a dynamic IP as a persistent route, including
        # an IP shared by a newly configured host. Leave its active route alone.
        if ($record.Prefix -in $configuredPrefixes) {
            if ([int]$record.InterfaceIndex -ne [int]$gateway.IfIndex -or
                [string]$record.NextHop -ne [string]$gateway.Gateway) {
                Remove-MonitorRouteRecord -Record $record
            }
            continue
        }
        if ($record.Kind -ne "Element" -and $record.Domain -and
            -not (Test-MonitoredDomain -Domain $record.Domain -ExactDomains $exactDomains -Suffixes $monitorSuffixes)) {
            Remove-MonitorRouteRecord -Record $record
            continue
        }
        $trackedRoutes[[string]$record.Prefix] = Set-MonitorRouteGateway -Record $record -Gateway $gateway
    }

    $lastResolve = [DateTime]::MinValue
    $lastSave = [DateTime]::MinValue
    $lastGatewayWarning = [DateTime]::MinValue
    $lastDnsCheck = [DateTime]::MinValue
    $consecutiveDnsFailures = 0
    $dnsOutageLogged = $false
    Write-MonitorLog "Started: $($knownDomains.Count) domain(s), $($monitorSuffixes.Count) suffix(es); automatic interface-index migration enabled; state $($configuration.UpdatedAt) from $StateFile."

    while ($true) {
        $now = (Get-Date).ToUniversalTime()
        $latestConfiguration = Read-ManagedState
        if (-not $latestConfiguration -or
            [string]$latestConfiguration.UpdatedAt -ne [string]$configuration.UpdatedAt) {
            Write-MonitorLog "Managed configuration changed; exiting for the next scheduled run."
            exit 0
        }
        if (($now - $lastSave).TotalSeconds -ge 30) {
            try {
                Save-MonitorState -RouteIndex $trackedRoutes
                $lastSave = $now
            } catch {
                Write-MonitorLog "WARNING: could not save monitor heartbeat: $($_.Exception.Message)"
            }
        }
        $currentGateway = Find-RealGateway
        if (-not $currentGateway) {
            if (($now - $lastGatewayWarning).TotalMinutes -ge 1) {
                Write-MonitorLog "LAN gateway unavailable; waiting for network recovery."
                $lastGatewayWarning = $now
            }
            Start-Sleep -Seconds $MonitorPollSeconds
            continue
        }
        if ($currentGateway -and (
            $currentGateway.IfIndex -ne $gateway.IfIndex -or
            $currentGateway.Gateway -ne $gateway.Gateway
        )) {
            try {
                $configuration = Update-ManagedGateway -Configuration $configuration -Gateway $currentGateway
                $gateway = $currentGateway
                foreach ($prefix in @($trackedRoutes.Keys)) {
                    $trackedRoutes[$prefix] = Set-MonitorRouteGateway -Record $trackedRoutes[$prefix] -Gateway $gateway
                }
                Save-MonitorState -RouteIndex $trackedRoutes
                $lastDnsCheck = [DateTime]::MinValue
            } catch {
                Write-MonitorLog "WARNING: could not update LAN gateway/index; will retry: $($_.Exception.Message)"
                Start-Sleep -Seconds $MonitorPollSeconds
                continue
            }
        }
        $gatewayRoute = Get-NetRoute `
            -DestinationPrefix "0.0.0.0/0" `
            -InterfaceIndex $gateway.IfIndex `
            -PolicyStore ActiveStore `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $gateway.Gateway } |
            Select-Object -First 1
        if (-not $gatewayRoute) {
            if (($now - $lastGatewayWarning).TotalMinutes -ge 1) {
                Write-MonitorLog "LAN gateway unavailable; waiting for network recovery."
                $lastGatewayWarning = $now
            }
            Start-Sleep -Seconds $MonitorPollSeconds
            continue
        }

        $lastGatewayWarning = [DateTime]::MinValue
        $cutoff = $now.AddHours(-$MonitorRouteRetentionHours)
        $activeDirect = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($route in @(
            Get-NetRoute `
                -InterfaceIndex $gateway.IfIndex `
                -PolicyStore ActiveStore `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.NextHop -eq $gateway.Gateway }
        )) {
            [void]$activeDirect.Add([string]$route.DestinationPrefix)
        }

        $changed = $false
        foreach ($prefix in @($trackedRoutes.Keys)) {
            $record = $trackedRoutes[$prefix]
            [DateTime]$lastSeen = [DateTime]::MinValue
            $validLastSeen = [DateTime]::TryParse(
                [string]$record.LastSeen,
                [ref]$lastSeen
            )
            if (
                -not $validLastSeen -or
                $lastSeen -eq [DateTime]::MinValue -or
                $lastSeen.ToUniversalTime() -lt $cutoff
            ) {
                Remove-MonitorRouteRecord -Record $record
                [void]$trackedRoutes.Remove($prefix)
                [void]$activeDirect.Remove($prefix)
                $changed = $true
                continue
            }
            if (-not $activeDirect.Contains($prefix)) {
                try {
                    New-NetRoute `
                        -DestinationPrefix $prefix `
                        -InterfaceIndex $gateway.IfIndex `
                        -NextHop $gateway.Gateway `
                        -RouteMetric $RouteMetric `
                        -PolicyStore ActiveStore `
                        -ErrorAction Stop |
                        Out-Null
                    [void]$activeDirect.Add($prefix)
                    $changed = $true
                } catch {
                    Write-MonitorLog "WARNING: could not restore ${prefix}: $($_.Exception.Message)"
                }
            }
        }

        if (-not $useSystemDns -and ($now - $lastDnsCheck).TotalSeconds -ge $MonitorDnsCheckSeconds) {
            $dnsAvailable = $false
            foreach ($server in $dnsServers) {
                if (Test-DnsServer -Server $server -SkipCacheClear) {
                    $dnsAvailable = $true
                    break
                }
            }
            if ($dnsAvailable) {
                $dnsAvailable = Test-EffectiveManagedDns
            }
            if (-not $dnsAvailable) {
                $consecutiveDnsFailures = [Math]::Min(
                    $consecutiveDnsFailures + 1,
                    $MonitorDnsFailureThreshold
                )
                if (-not $dnsOutageLogged) {
                    Write-MonitorLog "WARNING: saved DNS servers failed check $consecutiveDnsFailures/$MonitorDnsFailureThreshold."
                }
                if ($consecutiveDnsFailures -ge $MonitorDnsFailureThreshold) {
                    $alternativeDns = @(
                        @(Get-LanDnsServers -Gateway $gateway) + $PublicDnsServers + @(Get-CurrentVpnDnsServers) |
                            Where-Object { $_ -and $_ -notin $dnsServers } |
                            Select-Object -Unique
                    )
                    $replacementAvailable = $false
                    foreach ($server in $alternativeDns) {
                        if (Test-DnsServer -Server $server -SkipCacheClear) {
                            $replacementAvailable = $true
                            break
                        }
                    }
                    if ($replacementAvailable) {
                        Write-MonitorLog "Saved DNS servers remain unavailable; alternate DNS responds; refreshing configuration."
                        try { Request-ConfigurationRefresh } catch {
                            Write-MonitorLog "ERROR: could not start configuration refresh: $($_.Exception.Message)"
                        }
                        exit 1
                    }
                    if (-not $dnsOutageLogged) {
                        Write-MonitorLog "No DNS server responds; waiting for connectivity without changing routes."
                        $dnsOutageLogged = $true
                    }
                    $consecutiveDnsFailures = $MonitorDnsFailureThreshold
                }
            } else {
                $consecutiveDnsFailures = 0
                $dnsOutageLogged = $false
            }
            $lastDnsCheck = $now
        }
        $candidates = @{}

        try {
            $candidates = Get-MonitoredCacheCandidates `
                -Entries @(Get-DnsClientCache -ErrorAction SilentlyContinue) `
                -ExactDomains $exactDomains `
                -Suffixes $monitorSuffixes
        } catch {
            Write-MonitorLog "WARNING: DNS cache read failed: $($_.Exception.Message)"
        }

        if (($now - $lastResolve).TotalSeconds -ge $MonitorResolveSeconds) {
            try {
                # Refresh discovered hosts as well as built-in names. Their
                # routes retain the host name for 24 hours across worker restarts.
                $refreshDomains = @(
                    $knownDomains + @($trackedRoutes.Values | ForEach-Object { $_.Domain }) +
                        @($candidates.Values) |
                        Where-Object { $_ } | Select-Object -Unique
                )
                $resolved = Resolve-DomainMap `
                    -Domains $refreshDomains `
                    -DnsServers $dnsServers `
                    -Throttle 12
                foreach ($domain in $refreshDomains) {
                    foreach ($ip in @($resolved[$domain])) {
                        if (Test-MonitorIpv4 -Value ([string]$ip)) {
                            $candidates[[string]$ip] = $domain
                        }
                    }
                }
            } catch {
                Write-MonitorLog "WARNING: proactive DNS refresh failed: $($_.Exception.Message)"
            }
            $lastResolve = $now
        }

        foreach ($ip in @(Get-ElementRemoteAddresses)) {
            # Empty domain prevents IP addresses from being sent back to DNS.
            if (-not $candidates.ContainsKey($ip)) { $candidates[$ip] = "" }
        }
        foreach ($ip in $candidates.Keys) {
            $prefix = "$ip/32"
            if ($trackedRoutes.ContainsKey($prefix)) {
                $trackedRoutes[$prefix].LastSeen = $now.ToString("o")
                continue
            }
            if ($activeDirect.Contains($prefix)) { continue }

            try {
                New-NetRoute `
                    -DestinationPrefix $prefix `
                    -InterfaceIndex $gateway.IfIndex `
                    -NextHop $gateway.Gateway `
                    -RouteMetric $RouteMetric `
                    -PolicyStore ActiveStore `
                    -ErrorAction Stop |
                    Out-Null
                $trackedRoutes[$prefix] = [PSCustomObject]@{
                    Prefix = $prefix
                    InterfaceIndex = $gateway.IfIndex
                    NextHop = $gateway.Gateway
                    Metric = $RouteMetric
                    Kind = if ($candidates[$ip]) { "Monitor" } else { "Element" }
                    Domain = [string]$candidates[$ip]
                    LastSeen = $now.ToString("o")
                }
                [void]$activeDirect.Add($prefix)
                $changed = $true
                $sourceName = if ($candidates[$ip]) { $candidates[$ip] } else { "an Element connection" }
                Write-MonitorLog "Added $prefix for $sourceName."
            } catch {
                Write-MonitorLog "WARNING: could not add ${prefix}: $($_.Exception.Message)"
            }
        }

        if ($changed) {
            try {
                Save-MonitorState -RouteIndex $trackedRoutes
                $lastSave = $now
            } catch {
                Write-MonitorLog "WARNING: could not save monitor state: $($_.Exception.Message)"
            }
        }
        Start-Sleep -Seconds $MonitorPollSeconds
    }
}


function Show-DiagnosticReport {
    param([switch]$IncludePlan)

    Write-Host "Split-tunnel diagnosis (no settings changed)"
    Write-Host "User config: $ConfigFile"
    Write-Host "Apply log: $ApplyLogFile"
    Write-Host "  $($userConfig.Domains.Count) host(s), $($userConfig.Suffixes.Count) suffix(es), $($userConfig.Prefixes.Count) IPv4 prefix(es)"
    Write-Host "Element config host(s): $(@(Find-ElementDomains) -join ', ')"
    Write-Host "Element public TCP peer(s): $(@(Get-ElementRemoteAddresses) -join ', ')"
    $gateway = Find-RealGateway
    if ($gateway) {
        Write-Host "LAN gateway: $($gateway.Gateway), interface $($gateway.IfIndex) ($($gateway.Desc))"
    } else {
        Write-Host "LAN gateway: unavailable"
    }

    $state = Read-ManagedState
    if ($state) {
        Write-Host "Saved gateway: $($state.Gateway), interface $($state.InterfaceIndex); $(@($state.Routes).Count) route(s)"
        if ($state.DnsMode) { Write-Host "Saved DNS mode: $($state.DnsMode)" }
        if ($gateway -and (
            [int]$state.InterfaceIndex -ne [int]$gateway.IfIndex -or
            [string]$state.Gateway -ne [string]$gateway.Gateway
        )) {
            Write-Host "WARNING: saved gateway differs from the current LAN gateway."
        }
    } else {
        Write-Host "Saved configuration: absent"
    }

    $monitorTask = Get-ScheduledTask -TaskName $MonitorTaskName -ErrorAction SilentlyContinue
    $monitorFile = Get-Item -LiteralPath $MonitorStateFile -ErrorAction SilentlyContinue
    $taskState = if ($monitorTask) { [string]$monitorTask.State } else { "absent" }
    $heartbeat = if ($monitorFile) { $monitorFile.LastWriteTime.ToString("o") } else { "absent" }
    Write-Host "Monitor task: $taskState; last heartbeat: $heartbeat"
    if ($monitorTask -and $taskState -eq "Running" -and
        (-not $monitorFile -or $monitorFile.LastWriteTimeUtc -lt (Get-Date).ToUniversalTime().AddMinutes(-2))) {
        Write-Host "WARNING: monitor task is running but its heartbeat is stale."
    }

    $managedRules = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object { $_.Comment -eq $NrptComment })
    Write-Host "Managed NRPT rules: $($managedRules.Count)"
    foreach ($namespace in $NationalBypassSuffixes) {
        try {
            # Effective policy exposes IDN namespaces in Unicode, even when the rule was installed in Punycode.
            $policyNamespace = '.' + [Globalization.IdnMapping]::new().GetUnicode($namespace.Substring(1))
            $policy = Get-DnsClientNrptPolicy -Effective -Namespace $policyNamespace -ErrorAction Stop
            if ($policy) {
                Write-Host "Effective $namespace DNS: $(@($policy.NameServers) -join ', ')"
            } else {
                Write-Host "Effective $namespace NRPT policy: no rule returned"
            }
        } catch {
            if ($_.FullyQualifiedErrorId -match '\bWIN32 4312\b') {
                Write-Host "Effective $namespace NRPT policy: no rule returned"
            } else {
                Write-Host "WARNING: could not read $namespace NRPT policy: $($_.Exception.Message)"
            }
        }
    }

    $lanDns = @()
    if ($gateway) { $lanDns = @(Get-LanDnsServers -Gateway $gateway) }
    $vpnDns = @(Get-CurrentVpnDnsServers)
    Write-Host "LAN DNS: $($lanDns -join ', '); VPN DNS candidates: $($vpnDns -join ', ')"
    foreach ($server in @($lanDns + $PublicDnsServers + $vpnDns | Where-Object { $_ } | Select-Object -Unique)) {
        $result = if (Test-DnsServer -Server $server -SkipCacheClear) { "OK" } else { "FAILED" }
        Write-Host "  [DNS] $server  [$result]"
    }
    foreach ($server in $vpnDns) {
        foreach ($domain in $DnsCriticalNames) {
            if (Test-DnsServer -Server $server -Name $domain -SkipCacheClear) {
                $result = "OK"
            } elseif (@(Resolve-IpsWithNslookup -Domain $domain -Server $server).Count -gt 0) {
                $result = "OK via nslookup"
            } else {
                $result = "FAILED"
            }
            Write-Host "  [VPN DNS] $server -> $domain  [$result]"
        }
    }
    foreach ($domain in @($DnsProbeName) + $SystemDnsProbeNames) {
        $ips = @(Resolve-Ips -Domain $domain -DnsServers @())
        $result = if ($ips.Count -gt 0) { "OK" } else { "NO USABLE IPv4 ANSWER" }
        Write-Host "  [System DNS] $domain  [$result]"
        if ($gateway -and $domain -in $BypassZoneProbeNames) {
            foreach ($ip in $ips) {
                $route = Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue |
                    Where-Object { $_.DestinationPrefix } | Select-Object -First 1
                $path = if (-not $route) {
                    "unavailable"
                } elseif ($route.InterfaceIndex -eq $gateway.IfIndex -and $route.NextHop -eq $gateway.Gateway) {
                    "LAN/Wi-Fi gateway"
                } else {
                    "interface $($route.InterfaceIndex), next hop $($route.NextHop)"
                }
                Write-Host "  [Windows route] $domain -> $ip [$path]"
            }
        }
    }

    if ($IncludePlan) {
        $domains = @(
            @($Apps.Values | ForEach-Object { $_ }) +
                @($BypassSeedDomains) + @($CustomSiteDomains) + @($ZoteroWebDavUrls) |
                Where-Object { $_ } | Select-Object -Unique
        )
        Write-Host "Plan: rediscover DNS and IPv4 addresses for at least $($domains.Count) configured host(s)."
        Write-Host "Plan: reconcile $($StaticBypassPrefixes.Count) static route group(s), managed NRPT rules and the route monitor."
        Write-Host "Exact /32 routes depend on DNS answers at apply time."
    }
}


# ---- main ----

if ($Help) {
    Get-Help -Name $PSCommandPath -Detailed | Out-Host
    exit 0
}

if ($EditConfig) {
    try { Open-BypassConfig } catch {
        Write-Host "ERROR: could not open user config: $($_.Exception.Message)"
        exit 1
    }
    exit 0
}

# A malformed user file must never block removal or stop an installed worker
# from maintaining its last successfully applied configuration.
if (-not $Remove -and -not $Worker) {
    try { $userConfig = Read-BypassConfig } catch {
        Write-Host "ERROR: $($_.Exception.Message)"
        exit 1
    }
    $protectedEntries = @($userConfig.Domains + $userConfig.Suffixes | Where-Object { Test-VpnOnlyDomain $_ })
    if ($protectedEntries.Count) {
        Write-Host "ERROR: Remove VPN-only names from bypass_domains.txt: $($protectedEntries -join ', ')"
        exit 1
    }
    $CustomSiteDomains = @($CustomSiteDomains) + @($userConfig.Domains)
    $BypassDomainSuffixes = @($BypassDomainSuffixes) + @($userConfig.Suffixes)
    if ($userConfig.Prefixes.Count -gt 0) { $StaticBypassPrefixes["Custom IP networks"] = @($userConfig.Prefixes) }
    if ($CheckConfig) {
        Write-Host "OK: $ConfigFile"
        Write-Host "$($userConfig.Domains.Count) host(s), $($userConfig.Suffixes.Count) suffix(es), $($userConfig.Prefixes.Count) IPv4 prefix(es)."
        exit 0
    }
}

if ($Diagnose -or $Plan) {
    Show-DiagnosticReport -IncludePlan:$Plan
    exit 0
}

if ($Worker) {
    Start-RouteMonitor
    exit 0
}

if (-not (Test-IsAdmin)) {
    Write-Host "Requesting Administrator privileges..."
    $argumentLine = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Packaged) { $argumentLine += ' -Packaged' }
    if ($Remove) { $argumentLine += " -Remove" }
    try {
        $process = Start-Process `
            -FilePath (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') `
            -ArgumentList $argumentLine `
            -Verb RunAs `
            -WindowStyle Normal `
            -PassThru `
            -Wait `
            -ErrorAction Stop
        exit $process.ExitCode
    } catch {
        Write-Host "ERROR: Administrator elevation was cancelled or failed: $($_.Exception.Message)"
        exit 1
    }
}

try {
    Start-Transcript -Path $ApplyLogFile -Force -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "Could not start apply log: $($_.Exception.Message)"
}

if ($Remove) {
    Write-Host "Removing split-tunnel routes, monitor and conditional DNS rules..."
    Stop-RouteMonitorTask -Unregister
    Remove-RouteMonitorRoutes
    Remove-PreviousManagedState
    Write-Host "Removed. No routes, monitor task or NRPT rules managed by this script remain."
    exit 0
}

Write-Host "Looking for the real (non-VPN) network gateway..."
$gateway = Find-RealGateway
if (-not $gateway) {
    Write-Host "ERROR: could not find a non-VPN default gateway."
    Write-Host "The VPN may have removed the local default route or may not be route-based."
    exit 1
}
Write-Host "Using gateway $($gateway.Gateway) via interface $($gateway.IfIndex) ($($gateway.Desc))"

$runtimeApps = [ordered]@{}
foreach ($key in $Apps.Keys) { $runtimeApps[$key] = $Apps[$key] }
$elementDomains = @(Find-ElementDomains)
if ($elementDomains.Count -gt 0) {
    $runtimeApps["Element / Matrix"] = @($runtimeApps["Element / Matrix"] + $elementDomains | Select-Object -Unique)
    Write-Host "Auto-detected Element server(s): $($elementDomains -join ', ')"
}

$normalizedCustomSites = @(ConvertTo-DomainList -Values $CustomSiteDomains)
if ($normalizedCustomSites.Count -gt 0) {
    $runtimeApps["Custom sites"] = $normalizedCustomSites
    Write-Host "Configured custom site(s): $($normalizedCustomSites -join ', ')"
}

$bypassSuffixes = @(ConvertTo-SuffixList -Values $BypassDomainSuffixes)
$bypassSeedDomains = @(ConvertTo-DomainList -Values $BypassSeedDomains)
$bypassDomains = @($bypassSeedDomains)
if ($bypassSuffixes.Count -gt 0) {
    Write-Host "Bypassed domain suffix(es): $($bypassSuffixes -join ', ')"
    $cachedBypassDomains = @(
        Find-CachedDomainsForSuffixes -Suffixes $bypassSuffixes |
            Where-Object { $_ -notin $bypassSeedDomains }
    )
    if ($cachedBypassDomains.Count -gt 0) {
        Write-Host "Found $($cachedBypassDomains.Count) more host(s) under those suffixes in the Windows DNS cache."
    }
    $bypassDomains = @($bypassDomains + $cachedBypassDomains)
}
if ($bypassDomains.Count -gt 0) {
    $bypassGroupName = "Suffix bypass"
    if ($bypassSuffixes.Count -gt 0) {
        $bypassGroupName = "Suffix bypass ($($bypassSuffixes -join ', '))"
    }
    $runtimeApps[$bypassGroupName] = $bypassDomains
    Write-Host "Host(s) to route under the bypassed suffixes: $($bypassDomains.Count)"
}

$detectedZoteroDomains = @(Find-ZoteroWebDavDomains)
if ($detectedZoteroDomains.Count -gt 0) {
    Write-Host "Auto-detected Zotero WebDAV host(s): $($detectedZoteroDomains -join ', ')"
} else {
    Write-Host "No WebDAV host found in the Zotero profile; using the configured list only."
}
$zoteroWebDavDomains = @(
    ConvertTo-DomainList -Values (@($ZoteroWebDavUrls) + $detectedZoteroDomains)
)
if ($zoteroWebDavDomains.Count -gt 0) {
    $runtimeApps["Zotero WebDAV"] = $zoteroWebDavDomains
    Write-Host "Zotero WebDAV host(s) to bypass: $($zoteroWebDavDomains -join ', ')"
}

$youGileShards = @(Find-YouGileShardDomains)
if ($youGileShards.Count -gt 0) {
    $runtimeApps["YouGile"] = @($runtimeApps["YouGile"] + $youGileShards | Select-Object -Unique)
    Write-Host "Auto-detected YouGile shard(s): $($youGileShards -join ', ')"
}

$bitrixDesktopDomains = @(Find-Bitrix24DesktopDomains)
if ($bitrixDesktopDomains.Count -gt 0) {
    $runtimeApps["Bitrix24 cloud"] = @(
        $runtimeApps["Bitrix24 cloud"] + $bitrixDesktopDomains |
            Select-Object -Unique
    )
    Write-Host "Auto-detected Bitrix24 desktop host(s): $($bitrixDesktopDomains -join ', ')"
}

$nextcloudDomain = Find-NextcloudDomain
if ($nextcloudDomain) {
    $runtimeApps["Nextcloud"] = @($nextcloudDomain)
    Write-Host "Auto-detected Nextcloud server: $nextcloudDomain"
} else {
    $runtimeApps["Nextcloud"] = @()
    Write-Host "Could not auto-detect Nextcloud domain; Nextcloud is skipped."
}

Write-Host "Preparing the previous managed configuration for an in-place update..."
$previousState = Read-ManagedState
$previousManagedRoutes = @()
$savedNrptRuleNames = @()
if ($previousState) {
    $hasVersion = $previousState.PSObject.Properties.Name -contains "Version"
    if ($hasVersion -and [int]$previousState.Version -ge 2) {
        $previousManagedRoutes = @($previousState.Routes)
        $savedNrptRuleNames = @($previousState.NrptRuleNames)
    } else {
        foreach ($prefix in @($previousState)) { Remove-LegacyRoute $prefix }
    }
}
Clear-DnsClientCache -ErrorAction SilentlyContinue

$activeRouteIndex = @{}
$activeManagedCandidateIndex = @{}
$activeRouteObjectIndex = @{}
foreach ($route in @(
    Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
)) {
    $identity = Get-RouteIdentity `
        -Prefix ([string]$route.DestinationPrefix) `
        -InterfaceIndex ([int]$route.InterfaceIndex) `
        -NextHop ([string]$route.NextHop)
    $activeRouteIndex[$identity] = $true
    if ([int]$route.RouteMetric -eq $RouteMetric -and [string]$route.Protocol -eq "NetMgmt") {
        $activeManagedCandidateIndex[$identity] = $true
        $activeRouteObjectIndex["$identity|$RouteMetric"] = $route
    }
}
$adoptableRouteIndex = @{}
$persistentRouteObjectIndex = @{}
foreach ($route in @(
    Get-NetRoute -AddressFamily IPv4 -PolicyStore PersistentStore -ErrorAction SilentlyContinue
)) {
    if ([int]$route.RouteMetric -ne $RouteMetric) { continue }
    $identity = Get-RouteIdentity `
        -Prefix ([string]$route.DestinationPrefix) `
        -InterfaceIndex ([int]$route.InterfaceIndex) `
        -NextHop ([string]$route.NextHop)
    $persistentRouteObjectIndex["$identity|$RouteMetric"] = $route
    if ($activeManagedCandidateIndex.ContainsKey($identity)) {
        $adoptableRouteIndex[$identity] = $true
    }
}

$managedRoutes = @()
$managedRouteIndex = @{}
$createdRoutes = @()
$workingDnsServers = @()
$dnsMode = ""

Write-Host ""
Write-Host "Checking LAN-configured and public DNS directly through LAN/Wi-Fi..."
$lanDnsServers = @(Get-LanDnsServers -Gateway $gateway)
foreach ($server in @($lanDnsServers + $PublicDnsServers | Select-Object -Unique)) {
    if (-not (Test-DnsDirectViaLan -Server $server -Gateway $gateway)) {
        Write-Host "  [DNS] $server -> direct LAN/Wi-Fi  [FAILED]"
        continue
    }

    $routeResult = Add-PersistentManagedRoute `
        -Ip $server `
        -Gateway $gateway `
        -Kind "DNS" `
        -ActiveRouteIndex $activeRouteIndex `
        -AdoptableRouteIndex $adoptableRouteIndex
    if (
        -not $routeResult.Ok -or
        -not (Test-DnsCandidate -Server $server -Report) -or
        -not (Test-DnsViaNrpt -Server $server -Report)
    ) {
        if ($routeResult.Created) {
            Remove-RouteRecord $routeResult.Record
            $identity = Get-RouteIdentity `
                -Prefix $routeResult.Record.Prefix `
                -InterfaceIndex $routeResult.Record.InterfaceIndex `
                -NextHop $routeResult.Record.NextHop
            [void]$activeRouteIndex.Remove($identity)
            [void]$adoptableRouteIndex.Remove($identity)
        }
        Write-Host "  [DNS] $server -> direct LAN/Wi-Fi  [FAILED TO APPLY]"
        continue
    }

    if ($routeResult.Record) {
        $identity = Get-RouteIdentity `
            -Prefix $routeResult.Record.Prefix `
            -InterfaceIndex $routeResult.Record.InterfaceIndex `
            -NextHop $routeResult.Record.NextHop
        if (-not $managedRouteIndex.ContainsKey($identity)) {
            $managedRoutes += $routeResult.Record
            $managedRouteIndex[$identity] = $true
        }
    }
    if ($routeResult.Created) { $createdRoutes += $routeResult.Record }
    $workingDnsServers += $server
    Write-Host "  [DNS] $server -> direct LAN/Wi-Fi  [OK]"
    if (-not (Test-DnsServer -Server $server -TcpOnly)) {
        Write-Host "        WARNING: TCP DNS is blocked; ordinary UDP DNS still works."
    }
}
if ($workingDnsServers.Count -gt 0) {
    $dnsMode = "ExplicitLan"
} else {
    Write-Host "Direct public DNS is unavailable; testing the current route as a fallback..."
    foreach ($server in $PublicDnsServers) {
        if ((Test-DnsCandidate -Server $server -Report) -and (Test-DnsViaNrpt -Server $server -Report)) {
            Write-Host "  [DNS] $server -> current route  [OK]"
            $workingDnsServers += $server
        } else {
            Write-Host "  [DNS] $server -> current route  [FAILED]"
        }
    }
    if ($workingDnsServers.Count -gt 0) {
        $dnsMode = "CurrentRoute"
        Write-Host "        WARNING: DNS fallback uses the VPN/current route."
    } else {
        Write-Host "Public DNS is unavailable; testing DNS servers of active VPN adapters..."
        foreach ($server in @(Get-CurrentVpnDnsServers)) {
            if ((Test-DnsCandidate -Server $server -Report) -and (Test-DnsViaNrpt -Server $server -Report)) {
                $workingDnsServers += $server
                Write-Host "  [DNS] $server -> active VPN adapter  [OK]"
            }
        }
        if ($workingDnsServers.Count -gt 0) { $dnsMode = "VpnAdapter" }
    }
}

$workingDnsServers = @($workingDnsServers | Select-Object -Unique)
$script:PreviousManagedNrptRules = @(
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Comment -eq $NrptComment -or
            [string]$_.Name -in @($savedNrptRuleNames)
        } |
        ForEach-Object {
            [pscustomobject]@{
                Namespace = @([string[]]$_.Namespace)
                NameServers = @([string[]]$_.NameServers)
                DisplayName = [string]$_.DisplayName
            }
        }
)
$createdNrptNames = @()
if ($workingDnsServers.Count -eq 0) {
    $dnsMode = "System"
    Write-Host "No explicit DNS passed the checks. Resolving managed services through the Windows DNS client."
    if ($script:PreviousManagedNrptRules.Count -gt 0) {
        $script:NrptTouched = $true
        try {
            Sync-ManagedNrptRules -Namespaces @() -NameServers @() -PreviousRuleNames $savedNrptRuleNames | Out-Null
            Clear-DnsClientCache -ErrorAction SilentlyContinue
        } catch {
            Write-Host "ERROR: could not remove previous split-tunnel DNS rules: $($_.Exception.Message)"
            Rollback-CurrentRun $createdRoutes
            exit 1
        }
    }
}
Write-Host ""
Write-Host "Adding persistent static service-network routes:"
foreach ($routeGroupName in $StaticBypassPrefixes.Keys) {
    $staticRouteCount = 0
    foreach ($configuredPrefix in @($StaticBypassPrefixes[$routeGroupName])) {
        $prefixParts = @(([string]$configuredPrefix) -split "/", 2)
        $prefixLength = 0
        [Net.IPAddress]$networkAddress = $null
        if (
            $prefixParts.Count -ne 2 -or
            -not [int]::TryParse([string]$prefixParts[1], [ref]$prefixLength) -or
            $prefixLength -lt 0 -or
            $prefixLength -gt 32 -or
            -not [Net.IPAddress]::TryParse([string]$prefixParts[0], [ref]$networkAddress) -or
            $networkAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork
        ) {
            Write-Host "  [$routeGroupName] $configuredPrefix  [SKIPPED: invalid IPv4 prefix]"
            continue
        }

        $routeResult = Add-PersistentManagedRoute `
            -Ip $networkAddress.IPAddressToString `
            -PrefixLength $prefixLength `
            -Gateway $gateway `
            -Kind $routeGroupName `
            -ActiveRouteIndex $activeRouteIndex `
            -AdoptableRouteIndex $adoptableRouteIndex
        if (-not $routeResult.Ok) {
            Write-Host "  [$routeGroupName] $configuredPrefix  [FAILED: $($routeResult.Message)]"
            continue
        }

        if ($routeResult.Record) {
            $identity = Get-RouteIdentity `
                -Prefix $routeResult.Record.Prefix `
                -InterfaceIndex $routeResult.Record.InterfaceIndex `
                -NextHop $routeResult.Record.NextHop
            if (-not $managedRouteIndex.ContainsKey($identity)) {
                $managedRoutes += $routeResult.Record
                $managedRouteIndex[$identity] = $true
            }
        }
        if ($routeResult.Created) { $createdRoutes += $routeResult.Record }
        $staticRouteCount++
    }
    Write-Host "  [$routeGroupName] $staticRouteCount route(s) ready"
}


Write-Host ""
Write-Host "Resolving current app addresses and adding verified /32 routes:"
$allRuntimeDomains = @(
    $runtimeApps.Values |
        ForEach-Object { $_ } |
        Where-Object { $_ -and -not (Test-VpnOnlyDomain $_) } |
        Select-Object -Unique
)
$currentExactDomains = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($domain in $allRuntimeDomains) { [void]$currentExactDomains.Add($domain) }
$resolvedDomainMap = Resolve-DomainMap `
    -Domains $allRuntimeDomains `
    -DnsServers $workingDnsServers
$unresolvedDomains = @(
    $allRuntimeDomains |
        Where-Object { @($resolvedDomainMap[$_]).Count -eq 0 }
)
if ($unresolvedDomains.Count -gt 0) {
    Write-Host "  WARNING: no IPv4 answer for $($unresolvedDomains.Count) domain(s): $($unresolvedDomains -join ', ')"
}
$verifiedAppPrefixes = @()
$domainsByPrefix = @{}
foreach ($domain in $allRuntimeDomains) {
    foreach ($ip in @($resolvedDomainMap[$domain])) {
        if ($ip) { $domainsByPrefix["$ip/32"] = @($domainsByPrefix["$ip/32"]) + @($domain) }
    }
}
foreach ($appName in $runtimeApps.Keys) {
    $domains = @($runtimeApps[$appName])
    if ($domains.Count -eq 0) {
        Write-Host "  [$appName] skipped (no domain configured)"
        continue
    }

    $ips = @()
    foreach ($domain in $domains) {
        $ips += @($resolvedDomainMap[$domain])
    }
    $ips = @($ips | Select-Object -Unique)
    if ($ips.Count -eq 0) {
        Write-Host "  [$appName] no IPv4 address resolved  [FAILED]"
        continue
    }

    $appRouteCount = 0
    foreach ($ip in $ips) {
        $prefix = "$ip/32"
        if ($prefix -in $verifiedAppPrefixes) {
            $appRouteCount++
            continue
        }

        $routeResult = Add-PersistentManagedRoute `
            -Ip $ip `
            -Gateway $gateway `
            -Kind $appName `
            -ActiveRouteIndex $activeRouteIndex `
            -AdoptableRouteIndex $adoptableRouteIndex
        if ($routeResult.Ok) {
            if ($routeResult.Record) {
                $identity = Get-RouteIdentity `
                    -Prefix $routeResult.Record.Prefix `
                    -InterfaceIndex $routeResult.Record.InterfaceIndex `
                    -NextHop $routeResult.Record.NextHop
                if (-not $managedRouteIndex.ContainsKey($identity)) {
                    $managedRoutes += $routeResult.Record
                    $managedRouteIndex[$identity] = $true
                }
            }
            if ($routeResult.Created) { $createdRoutes += $routeResult.Record }
            $verifiedAppPrefixes += $prefix
            $appRouteCount++
        } else {
            Write-Host "  [$appName] $prefix  [FAILED: $($routeResult.Message)]"
        }
    }
    Write-Host "  [$appName] $appRouteCount route(s) ready"
}

$directPrefixIndex = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
foreach ($route in @(
    Get-NetRoute `
        -InterfaceIndex $gateway.IfIndex `
        -PolicyStore ActiveStore `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -eq $gateway.Gateway }
)) {
    [void]$directPrefixIndex.Add([string]$route.DestinationPrefix)
}
$uncoveredPrefixes = @(
    $resolvedDomainMap.Values |
        ForEach-Object { $_ } |
        Where-Object { $_ } |
        ForEach-Object { "$_/32" } |
        Select-Object -Unique |
        Where-Object { -not $directPrefixIndex.Contains($_) }
)
if ($uncoveredPrefixes.Count -gt 0) {
    Write-Host "ERROR: current service address(es) still use the VPN: $($uncoveredPrefixes -join ', ')"
    Rollback-CurrentRun $createdRoutes
    exit 1
}

if ($verifiedAppPrefixes.Count -eq 0) {
    Write-Host "ERROR: no application route could be prepared. No new changes were kept."
    if ($dnsMode -eq "System" -and $unresolvedDomains.Count -eq $allRuntimeDomains.Count) {
        Write-Host "Windows DNS returned no usable IPv4 addresses for any managed service. DNS timeouts and synthetic addresses cannot be used to create direct routes."
    }
    Rollback-CurrentRun $createdRoutes
    exit 1
}

$suffixNamespaces = @($NrptNamespaces + $bypassSuffixes | Where-Object { -not (Test-VpnOnlyDomain $_) } | Select-Object -Unique)
$effectiveNamespaces = @($suffixNamespaces)
foreach ($namespace in $suffixNamespaces) {
    # ".example.com" matches sub-domains only, so the zone apex needs a rule of
    # its own. A bare top-level suffix such as ".ru" has no apex host to add.
    if (-not $namespace.StartsWith(".")) { continue }
    $apex = $namespace.Substring(1)
    if ($apex.Contains(".")) { $effectiveNamespaces += $apex }
}
if ($nextcloudDomain) { $effectiveNamespaces += $nextcloudDomain }
foreach ($domain in $bypassDomains) {
    # Hosts already covered by a bypassed suffix need no rule of their own.
    if (Test-DomainUnderSuffix -Domain $domain -Suffixes $bypassSuffixes) { continue }
    $effectiveNamespaces += $domain
    $effectiveNamespaces += ".$domain"
}
foreach ($domain in $bitrixDesktopDomains) {
    $effectiveNamespaces += $domain
    $effectiveNamespaces += ".$domain"
}
foreach ($domain in $elementDomains) {
    $effectiveNamespaces += $domain
    $effectiveNamespaces += ".$domain"
}
foreach ($domain in $normalizedCustomSites) {
    $effectiveNamespaces += $domain
    $effectiveNamespaces += ".$domain"
}
foreach ($domain in $zoteroWebDavDomains) {
    $effectiveNamespaces += $domain
    $effectiveNamespaces += ".$domain"
}
$effectiveNamespaces = @($effectiveNamespaces | Where-Object { -not (Test-VpnOnlyDomain $_) } | Select-Object -Unique)

if ($dnsMode -ne "System") {
    Write-Host ""
    Write-Host "Installing conditional DNS rules for managed service namespaces..."
    $script:NrptTouched = $true
    try {
        $createdNrptNames = @(Sync-ManagedNrptRules `
            -Namespaces $effectiveNamespaces `
            -NameServers $workingDnsServers `
            -PreviousRuleNames $savedNrptRuleNames)
        Clear-DnsClientCache -ErrorAction SilentlyContinue
    } catch {
        Write-Host "ERROR: could not install NRPT rules: $($_.Exception.Message)"
        Rollback-CurrentRun $createdRoutes
        exit 1
    }

    $dnsVerificationNames = @("yougile.com", "pachca.com", "api.disk-o.cloud", "yandex.ru", "bitrix24.ru")
    if ($nextcloudDomain) { $dnsVerificationNames += $nextcloudDomain }
    $dnsVerificationErrors = @($dnsVerificationNames | Where-Object {
        @(Resolve-Ips -Domain $_ -DnsServers @()).Count -eq 0
    })
    if ($dnsVerificationErrors.Count -gt 0) {
        Write-Host "ERROR: effective system DNS verification failed: $($dnsVerificationErrors -join ', ')"
        Write-Host "A VPN policy or corporate NRPT policy may be overriding the local rules."
        Rollback-CurrentRun $createdRoutes
        exit 1
    }

    # Report unavailable optional services after installing NRPT. In System mode
    # the earlier lookup already reported all unavailable domains.
    $softVerificationNames = @(
        $zoteroWebDavDomains + $normalizedCustomSites + $bypassSeedDomains +
            $bitrixDesktopDomains + $elementDomains |
            Select-Object -Unique
    )
    foreach ($domain in $softVerificationNames) {
        if (@(Resolve-Ips -Domain $domain -DnsServers @()).Count -eq 0) {
            Write-Host "WARNING: $domain did not resolve; its bypass may be incomplete."
        }
    }
}

$installedManagedRouteIndex = @{}
foreach ($installed in @(
    Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue
)) {
    if ([int]$installed.RouteMetric -ne $RouteMetric) { continue }
    $identity = Get-RouteIdentity `
        -Prefix ([string]$installed.DestinationPrefix) `
        -InterfaceIndex ([int]$installed.InterfaceIndex) `
        -NextHop ([string]$installed.NextHop)
    $installedManagedRouteIndex[$identity] = $true
}
foreach ($route in $managedRoutes) {
    $identity = Get-RouteIdentity `
        -Prefix ([string]$route.Prefix) `
        -InterfaceIndex ([int]$route.InterfaceIndex) `
        -NextHop ([string]$route.NextHop)
    if (-not $installedManagedRouteIndex.ContainsKey($identity)) {
        Write-Host "ERROR: final route verification failed for $($route.Prefix)."
        Rollback-CurrentRun $createdRoutes
        exit 1
    }
}

$staleManagedRoutes = @()
$retentionCutoff = (Get-Date).ToUniversalTime().AddHours(-$MonitorRouteRetentionHours)
$previousUpdatedAt = [DateTime]::MinValue
if ($previousState) {
    [void][DateTime]::TryParse([string]$previousState.UpdatedAt, [ref]$previousUpdatedAt)
}
foreach ($route in $previousManagedRoutes) {
    $identity = Get-RouteIdentity `
        -Prefix ([string]$route.Prefix) `
        -InterfaceIndex ([int]$route.InterfaceIndex) `
        -NextHop ([string]$route.NextHop)
    if ($managedRouteIndex.ContainsKey($identity)) { continue }

    $lastSeen = [DateTime]::MinValue
    if ($route.PSObject.Properties.Name -contains "LastSeen") {
        [void][DateTime]::TryParse([string]$route.LastSeen, [ref]$lastSeen)
    }
    if ($lastSeen -eq [DateTime]::MinValue) { $lastSeen = $previousUpdatedAt }
    $lastSeenIsUsable = ($lastSeen -ne [DateTime]::MinValue)
    $sameGateway = (
        [int]$route.InterfaceIndex -eq [int]$gateway.IfIndex -and
        [string]$route.NextHop -eq [string]$gateway.Gateway
    )
    $canRetain = (
        $sameGateway -and
        $lastSeenIsUsable -and
        $lastSeen.ToUniversalTime() -ge $retentionCutoff -and
        $adoptableRouteIndex.ContainsKey($identity)
    )
    if ($route.Kind -eq "DNS" -or
        ($route.Prefix -like "*/32" -and -not (Test-MonitorIpv4 ($route.Prefix -split '/', 2)[0]))) {
        $canRetain = $false
    }
    # Explicitly removed user entries must stop bypassing after re-apply,
    # while still retaining rotating addresses of configured hosts for 24h.
    if ($route.Kind -eq "Custom IP networks" -and $route.Prefix -notin @($userConfig.Prefixes)) {
        $canRetain = $false
    }
    if ($route.PSObject.Properties.Name -contains "Domains") {
        $stillMonitored = @($route.Domains | Where-Object {
            Test-MonitoredDomain -Domain $_ -ExactDomains $currentExactDomains -Suffixes $suffixNamespaces
        })
        if ($stillMonitored.Count -eq 0) { $canRetain = $false }
    }
    if ($canRetain) {
        $retainedRoute = [PSCustomObject]@{
            Prefix = [string]$route.Prefix
            InterfaceIndex = [int]$route.InterfaceIndex
            NextHop = [string]$route.NextHop
            Metric = [int]$route.Metric
            Kind = [string]$route.Kind
            LastSeen = $lastSeen.ToUniversalTime().ToString("o")
        }
        if ($route.PSObject.Properties.Name -contains "Domains") {
            $retainedRoute | Add-Member -NotePropertyName Domains -NotePropertyValue @($route.Domains)
        }
        $managedRoutes += $retainedRoute
        $managedRouteIndex[$identity] = $true
    } else {
        $staleManagedRoutes += $route
    }
}
Remove-RouteRecords `
    -Records $staleManagedRoutes `
    -ActiveRouteObjectIndex $activeRouteObjectIndex `
    -PersistentRouteObjectIndex $persistentRouteObjectIndex
foreach ($route in $managedRoutes) {
    if ($domainsByPrefix.ContainsKey([string]$route.Prefix)) {
        $route | Add-Member -NotePropertyName Domains -NotePropertyValue @($domainsByPrefix[[string]$route.Prefix] | Where-Object { $_ }) -Force
    }
}
$state = [ordered]@{
    Version = 3
    UpdatedAt = (Get-Date).ToUniversalTime().ToString("o")
    Gateway = [string]$gateway.Gateway
    InterfaceIndex = [int]$gateway.IfIndex
    InterfaceDescription = [string]$gateway.Desc
    DnsMode = $dnsMode
    DnsServers = @($workingDnsServers)
    Routes = @($managedRoutes)
    NrptRuleNames = @($createdNrptNames)
    MonitorDomains = @($allRuntimeDomains)
    MonitorSuffixes = @($suffixNamespaces | Where-Object { $_.StartsWith(".") })
}

try {
    $temporaryStateFile = $StateFile + ".tmp"
    $state | ConvertTo-Json -Depth 6 -ErrorAction Stop |
        Set-Content -LiteralPath $temporaryStateFile -Encoding UTF8 -ErrorAction Stop
    Move-Item `
        -LiteralPath $temporaryStateFile `
        -Destination $StateFile `
        -Force `
        -ErrorAction Stop
    $savedState = Get-Content -LiteralPath $StateFile -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if (
        [int]$savedState.Version -ne 3 -or
        @($savedState.MonitorDomains).Count -eq 0
    ) {
        throw "state verification failed"
    }
} catch {
    Write-Host "ERROR: could not save managed state: $($_.Exception.Message)"
    Rollback-CurrentRun $createdRoutes
    exit 1
}

try {
    Register-RouteMonitorTask
    Write-Host "Route monitor task '$MonitorTaskName' is running."
} catch {
    Write-Host "ERROR: routes are installed, but the route monitor could not start: $($_.Exception.Message)"
    exit 1
}

Write-Host ""
Write-Host "Done. $($verifiedAppPrefixes.Count) application route(s) bypass the VPN via LAN/Wi-Fi."
if ($dnsMode -eq "System") {
    Write-Host "DNS mode: System (Windows DNS; no split-tunnel NRPT rules)."
} else {
    Write-Host "DNS mode: $dnsMode; resolver(s): $($workingDnsServers -join ', ')."
}
if ($zoteroWebDavDomains.Count -gt 0) {
    Write-Host "Zotero WebDAV bypass active for: $($zoteroWebDavDomains -join ', ')."
}
if ($bypassSuffixes.Count -gt 0) {
    if ($dnsMode -eq "ExplicitLan") {
        Write-Host "DNS for $($bypassSuffixes -join ', ') is resolved directly; $($bypassDomains.Count) host(s) of those zones are routed."
    }
    Write-Host "New addresses from those zones are routed automatically from the DNS cache."
}
Write-Host "Restart affected apps so they open new connections with the updated DNS/routes."
Write-Host "Re-run after changing VPN settings if the monitor cannot recover automatically."
