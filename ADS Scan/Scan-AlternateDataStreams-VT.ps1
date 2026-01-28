<#
.SYNOPSIS
    NTFS Alternate Data Stream Scanner with Multi-Service Threat Intelligence v2.0

.DESCRIPTION
    Advanced security auditing tool for scanning Windows NTFS filesystems for Alternate Data Streams (ADS)
    with integrated threat intelligence from VirusTotal and Hybrid Analysis. Supports multiple API keys
    per service with automatic rotation, results caching, and multiple export formats.

.PARAMETER Path
    The path or drive to scan (e.g., "C:\Users", "D:\")

.PARAMETER OutputFile
    The path where the report will be saved (default: ADS_Report_<timestamp>.<format>)

.PARAMETER ExportFormat
    Export format: CSV, JSON, HTML, or STIX (default: CSV)

.PARAMETER UseConfig
    Use API keys and settings from configuration file

.PARAMETER ExcludeZoneIdentifier
    Switch to exclude Zone.Identifier streams from the report

.PARAMETER VirusTotalAPIKey
    VirusTotal API key (legacy mode, single key)

.PARAMETER SkipVirusTotal
    Skip VirusTotal lookups entirely

.PARAMETER SkipHybridAnalysis
    Skip Hybrid Analysis lookups

.PARAMETER ResumeFile
    Path to a previous scan CSV to resume from

.PARAMETER Proxy
    Proxy URL (e.g., http://proxy:8080)

.PARAMETER NoCache
    Disable results caching

.PARAMETER NoParallel
    Disable parallel API calls

.PARAMETER LogLevel
    Logging level: DEBUG, INFO, WARNING, ERROR (default: INFO)

.PARAMETER ConfigAction
    Configuration management action: Init, Add, List, Remove, Test

.PARAMETER Service
    Service name for config actions: VirusTotal, HybridAnalysis

.PARAMETER Key
    API key for config actions

.PARAMETER Tier
    API tier for config add: Free, Paid

.PARAMETER Index
    Key index for config remove

.PARAMETER InteractiveSetup
    Run interactive setup wizard

.EXAMPLE
    .\Scan-AlternateDataStreams-VT.ps1 -InteractiveSetup

.EXAMPLE
    .\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig

.EXAMPLE
    .\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig -ExportFormat HTML

.EXAMPLE
    .\Scan-AlternateDataStreams-VT.ps1 -ConfigAction Add -Service VirusTotal -Key "YOUR_KEY" -Tier Free

.EXAMPLE
    .\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -VirusTotalAPIKey "YOUR_KEY"

#>

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$Path,

    [Parameter()]
    [string]$OutputFile,

    [Parameter()]
    [ValidateSet('CSV', 'JSON', 'HTML', 'STIX')]
    [string]$ExportFormat = 'CSV',

    [Parameter()]
    [switch]$UseConfig,

    [Parameter()]
    [switch]$ExcludeZoneIdentifier,

    [Parameter()]
    [string]$VirusTotalAPIKey,

    [Parameter()]
    [switch]$SkipVirusTotal,

    [Parameter()]
    [switch]$SkipHybridAnalysis,

    [Parameter()]
    [string]$ResumeFile,

    [Parameter()]
    [string]$Proxy,

    [Parameter()]
    [switch]$NoCache,

    [Parameter()]
    [switch]$NoParallel,

    [Parameter()]
    [ValidateSet('DEBUG', 'INFO', 'WARNING', 'ERROR')]
    [string]$LogLevel = 'INFO',

    # Configuration management
    [Parameter()]
    [ValidateSet('Init', 'Add', 'List', 'Remove', 'Test')]
    [string]$ConfigAction,

    [Parameter()]
    [ValidateSet('VirusTotal', 'HybridAnalysis')]
    [string]$Service,

    [Parameter()]
    [string]$Key,

    [Parameter()]
    [ValidateSet('Free', 'Paid')]
    [string]$Tier = 'Free',

    [Parameter()]
    [int]$Index,

    [Parameter()]
    [switch]$InteractiveSetup
)

#region Configuration Manager

class ADSConfigManager {
    [string]$ConfigDir
    [string]$ConfigFile
    [string]$CacheDir
    [string]$LogDir
    [hashtable]$Config

    ADSConfigManager() {
        $localAppData = [Environment]::GetFolderPath('LocalApplicationData')
        $this.ConfigDir = Join-Path $localAppData 'ADSScanner'
        $this.ConfigFile = Join-Path $this.ConfigDir 'config.json'
        $this.CacheDir = Join-Path $this.ConfigDir 'cache'
        $this.LogDir = Join-Path $this.ConfigDir 'logs'
    }

    [void] Initialize() {
        # Create directories
        if (-not (Test-Path $this.ConfigDir)) {
            New-Item -Path $this.ConfigDir -ItemType Directory -Force | Out-Null
        }
        if (-not (Test-Path $this.CacheDir)) {
            New-Item -Path $this.CacheDir -ItemType Directory -Force | Out-Null
        }
        if (-not (Test-Path $this.LogDir)) {
            New-Item -Path $this.LogDir -ItemType Directory -Force | Out-Null
        }

        # Create default config if not exists
        if (-not (Test-Path $this.ConfigFile)) {
            $this.CreateDefaultConfig()
        }
    }

    [void] CreateDefaultConfig() {
        $defaultConfig = @{
            version = "1.0"
            api_keys = @{
                virustotal = @()
                hybrid_analysis = @()
            }
            settings = @{
                exclude_zone_identifier = $false
                default_output_path = $null
                parallel_api_calls = $true
                cache_enabled = $true
                cache_ttl_days = 7
                proxy = $null
                log_level = "INFO"
                export_format = "CSV"
            }
        }

        $this.Config = $defaultConfig
        $this.SaveConfig()
    }

    [void] LoadConfig() {
        if (-not (Test-Path $this.ConfigFile)) {
            throw "Configuration file not found: $($this.ConfigFile)"
        }

        $json = Get-Content -Path $this.ConfigFile -Raw
        $this.Config = $json | ConvertFrom-Json -AsHashtable
    }

    [void] SaveConfig() {
        $json = $this.Config | ConvertTo-Json -Depth 10
        $json | Set-Content -Path $this.ConfigFile -Encoding UTF8
    }

    [string] EncryptString([string]$plaintext) {
        if ([string]::IsNullOrEmpty($plaintext)) {
            return ""
        }

        $secureString = ConvertTo-SecureString -String $plaintext -AsPlainText -Force
        return ConvertFrom-SecureString -SecureString $secureString
    }

    [string] DecryptString([string]$encrypted) {
        if ([string]::IsNullOrEmpty($encrypted)) {
            return ""
        }

        $secureString = ConvertTo-SecureString -String $encrypted
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }

    [void] AddAPIKey([string]$service, [string]$apiKey, [string]$tier, [int]$priority, [bool]$enabled) {
        $service = $service.ToLower()

        # Set default rate limits
        $keyConfig = @{
            key = $this.EncryptString($apiKey)
            tier = $tier
            enabled = $enabled
            priority = $priority
        }

        if ($service -eq 'virustotal') {
            if ($tier -eq 'Free') {
                $keyConfig.requests_per_minute = 4
                $keyConfig.requests_per_day = 500
            } else {
                $keyConfig.requests_per_minute = 1000
                $keyConfig.requests_per_day = 300000
            }
        } elseif ($service -eq 'hybrid_analysis') {
            $keyConfig.requests_per_minute = 5
            $keyConfig.requests_per_hour = 200
        }

        # Add to config
        $this.Config.api_keys.$service += $keyConfig

        # Sort by priority
        $this.Config.api_keys.$service = $this.Config.api_keys.$service | Sort-Object priority

        $this.SaveConfig()
    }

    [void] RemoveAPIKey([string]$service, [int]$index) {
        $service = $service.ToLower()

        if ($index -lt 0 -or $index -ge $this.Config.api_keys.$service.Count) {
            throw "Invalid key index: $index"
        }

        $newArray = @()
        for ($i = 0; $i -lt $this.Config.api_keys.$service.Count; $i++) {
            if ($i -ne $index) {
                $newArray += $this.Config.api_keys.$service[$i]
            }
        }

        $this.Config.api_keys.$service = $newArray
        $this.SaveConfig()
    }

    [array] GetAPIKeys([string]$service) {
        $service = $service.ToLower()
        $decryptedKeys = @()

        foreach ($keyConfig in $this.Config.api_keys.$service) {
            $decrypted = $keyConfig.Clone()
            $decrypted.key = $this.DecryptString($keyConfig.key)
            $decryptedKeys += $decrypted
        }

        return $decryptedKeys
    }

    [array] ListAPIKeys([string]$service) {
        $service = $service.ToLower()
        $maskedKeys = @()

        $index = 0
        foreach ($keyConfig in $this.Config.api_keys.$service) {
            $masked = $keyConfig.Clone()
            $encKey = $keyConfig.key
            if ($encKey.Length -gt 8) {
                $masked.key = "***" + $encKey.Substring($encKey.Length - 8)
            } else {
                $masked.key = "***"
            }
            $masked.index = $index
            $maskedKeys += $masked
            $index++
        }

        return $maskedKeys
    }

    [object] GetSetting([string]$name, [object]$default) {
        if ($this.Config.settings.ContainsKey($name)) {
            return $this.Config.settings.$name
        }
        return $default
    }

    [void] SetSetting([string]$name, [object]$value) {
        $this.Config.settings.$name = $value
        $this.SaveConfig()
    }

    [bool] ConfigExists() {
        return Test-Path $this.ConfigFile
    }
}

#endregion

#region API Clients

class VirusTotalAPIClient {
    [string]$APIKey
    [string]$BaseURL = "https://www.virustotal.com/api/v3"
    [string]$Proxy
    [int]$RequestsPerMinute = 4
    [int]$RequestsPerDay = 500
    [System.Collections.ArrayList]$RequestTimes
    [int]$DailyCount = 0

    VirusTotalAPIClient([string]$apiKey, [string]$proxy) {
        $this.APIKey = $apiKey
        $this.Proxy = $proxy
        $this.RequestTimes = New-Object System.Collections.ArrayList
    }

    [void] SetRateLimits([int]$rpm, [int]$rpd) {
        $this.RequestsPerMinute = $rpm
        $this.RequestsPerDay = $rpd
    }

    [bool] WaitForRateLimit() {
        # Check daily limit
        if ($this.DailyCount -ge $this.RequestsPerDay) {
            return $false
        }

        $now = Get-Date

        # Clean old request times
        $newTimes = New-Object System.Collections.ArrayList
        foreach ($time in $this.RequestTimes) {
            if (($now - $time).TotalSeconds -lt 60) {
                [void]$newTimes.Add($time)
            }
        }
        $this.RequestTimes = $newTimes

        # Check per-minute limit
        if ($this.RequestTimes.Count -ge $this.RequestsPerMinute) {
            $oldestTime = $this.RequestTimes[0]
            $sleepTime = 60 - ($now - $oldestTime).TotalSeconds
            if ($sleepTime -gt 0) {
                Write-Host "[*] VT rate limit: Waiting $([math]::Ceiling($sleepTime)) seconds..." -NoNewline -ForegroundColor Yellow
                Start-Sleep -Seconds ([math]::Ceiling($sleepTime))
                Write-Host " Done" -ForegroundColor Green
                $this.RequestTimes.Clear()
            }
        }

        return $true
    }

    [hashtable] LookupHash([string]$fileHash) {
        if (-not $this.WaitForRateLimit()) {
            return $null
        }

        $url = "$($this.BaseURL)/files/$fileHash"
        $headers = @{
            "x-apikey" = $this.APIKey
        }

        try {
            [void]$this.RequestTimes.Add((Get-Date))
            $this.DailyCount++

            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop

            $stats = $response.data.attributes.last_analysis_stats
            $malicious = $stats.malicious
            $suspicious = $stats.suspicious
            $undetected = $stats.undetected
            $harmless = $stats.harmless
            $total = $malicious + $suspicious + $undetected + $harmless

            $engines = @()
            foreach ($engine in $response.data.attributes.last_analysis_results.PSObject.Properties) {
                if ($engine.Value.category -eq "malicious") {
                    $engines += "$($engine.Name):$($engine.Value.result)"
                }
            }

            return @{
                found = $true
                malicious = $malicious
                suspicious = $suspicious
                undetected = $undetected
                harmless = $harmless
                total = $total
                detection_ratio = "$malicious/$total"
                detection_engines = ($engines -join "; ")
                scan_date = $response.data.attributes.last_analysis_date
                link = "https://www.virustotal.com/gui/file/$fileHash"
            }
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__

            if ($statusCode -eq 404) {
                return @{
                    found = $false
                    malicious = 0
                    suspicious = 0
                    undetected = 0
                    harmless = 0
                    total = 0
                    detection_ratio = "Not in VT DB"
                    detection_engines = ""
                    scan_date = ""
                    link = "https://www.virustotal.com/gui/file/$fileHash"
                }
            }
            elseif ($statusCode -eq 429) {
                Write-Host "[!] VT rate limit exceeded. Waiting 60 seconds..." -ForegroundColor Red
                Start-Sleep -Seconds 60
                return $this.LookupHash($fileHash)
            }
            else {
                Write-Warning "VT API error for hash $fileHash : $_"
                return $null
            }
        }
    }

    [bool] IsRateLimited() {
        return $this.DailyCount -ge $this.RequestsPerDay
    }

    [int] GetRemainingQuota() {
        return [Math]::Max(0, $this.RequestsPerDay - $this.DailyCount)
    }
}

class HybridAnalysisAPIClient {
    [string]$APIKey
    [string]$BaseURL = "https://www.hybrid-analysis.com/api/v2"
    [string]$Proxy
    [int]$RequestsPerMinute = 5
    [int]$RequestsPerHour = 200
    [System.Collections.ArrayList]$RequestTimes
    [int]$HourlyCount = 0
    [datetime]$LastHourReset

    HybridAnalysisAPIClient([string]$apiKey, [string]$proxy) {
        $this.APIKey = $apiKey
        $this.Proxy = $proxy
        $this.RequestTimes = New-Object System.Collections.ArrayList
        $this.LastHourReset = Get-Date
    }

    [void] SetRateLimits([int]$rpm, [int]$rph) {
        $this.RequestsPerMinute = $rpm
        $this.RequestsPerHour = $rph
    }

    [bool] WaitForRateLimit() {
        $now = Get-Date

        # Reset hourly counter if needed
        if (($now - $this.LastHourReset).TotalSeconds -ge 3600) {
            $this.HourlyCount = 0
            $this.LastHourReset = $now
        }

        # Check hourly limit
        if ($this.HourlyCount -ge $this.RequestsPerHour) {
            return $false
        }

        # Clean old request times
        $newTimes = New-Object System.Collections.ArrayList
        foreach ($time in $this.RequestTimes) {
            if (($now - $time).TotalSeconds -lt 60) {
                [void]$newTimes.Add($time)
            }
        }
        $this.RequestTimes = $newTimes

        # Check per-minute limit
        if ($this.RequestTimes.Count -ge $this.RequestsPerMinute) {
            $oldestTime = $this.RequestTimes[0]
            $sleepTime = 60 - ($now - $oldestTime).TotalSeconds
            if ($sleepTime -gt 0) {
                Write-Host "[*] HA rate limit: Waiting $([math]::Ceiling($sleepTime)) seconds..." -NoNewline -ForegroundColor Yellow
                Start-Sleep -Seconds ([math]::Ceiling($sleepTime))
                Write-Host " Done" -ForegroundColor Green
                $this.RequestTimes.Clear()
            }
        }

        return $true
    }

    [hashtable] LookupHash([string]$fileHash) {
        if (-not $this.WaitForRateLimit()) {
            return $null
        }

        $url = "$($this.BaseURL)/search/hash?hash=$fileHash"
        $headers = @{
            "api-key" = $this.APIKey
            "User-Agent" = "Falcon Sandbox"
            "accept" = "application/json"
        }

        try {
            [void]$this.RequestTimes.Add((Get-Date))
            $this.HourlyCount++

            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop

            if (-not $response -or $response.Count -eq 0) {
                return @{
                    found = $false
                    threat_score = 0
                    verdict = "no-verdict"
                    av_detect = 0
                    vx_family = ""
                    job_id = ""
                    report_url = ""
                    scan_date = ""
                }
            }

            $result = $response[0]
            $jobId = $result.job_id
            $reportUrl = if ($jobId) { "https://www.hybrid-analysis.com/sample/$jobId" } else { "" }

            return @{
                found = $true
                threat_score = $result.threat_score
                verdict = $result.verdict
                av_detect = $result.av_detect
                vx_family = $result.vx_family
                job_id = $jobId
                report_url = $reportUrl
                scan_date = $result.analysis_start_time
            }
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__

            if ($statusCode -eq 404) {
                return @{
                    found = $false
                    threat_score = 0
                    verdict = "no-verdict"
                    av_detect = 0
                    vx_family = ""
                    job_id = ""
                    report_url = ""
                    scan_date = ""
                }
            }
            elseif ($statusCode -eq 429) {
                Write-Host "[!] HA rate limit exceeded. Waiting 60 seconds..." -ForegroundColor Red
                Start-Sleep -Seconds 60
                return $this.LookupHash($fileHash)
            }
            else {
                Write-Warning "HA API error for hash $fileHash : $_"
                return $null
            }
        }
    }

    [bool] IsRateLimited() {
        return $this.HourlyCount -ge $this.RequestsPerHour
    }

    [int] GetRemainingQuota() {
        return [Math]::Max(0, $this.RequestsPerHour - $this.HourlyCount)
    }
}

#endregion

#region API Key Rotator

class APIKeyRotator {
    [string]$ServiceName
    [array]$Keys
    [int]$CurrentIndex = 0

    APIKeyRotator([string]$serviceName, [array]$keysConfig, [string]$proxy) {
        $this.ServiceName = $serviceName
        $this.Keys = @()

        foreach ($keyCfg in $keysConfig) {
            if (-not $keyCfg.enabled) { continue }

            $keyInfo = @{
                api_key = $keyCfg.key
                tier = $keyCfg.tier
                priority = $keyCfg.priority
                rpm = $keyCfg.requests_per_minute
                rpd = $keyCfg.requests_per_day
                rph = $keyCfg.requests_per_hour
                rate_limited_until = $null
                api_client = $null
            }

            # Create API client
            if ($serviceName -eq 'virustotal') {
                $client = [VirusTotalAPIClient]::new($keyCfg.key, $proxy)
                if ($keyInfo.rpm -and $keyInfo.rpd) {
                    $client.SetRateLimits($keyInfo.rpm, $keyInfo.rpd)
                }
                $keyInfo.api_client = $client
            }
            elseif ($serviceName -eq 'hybrid_analysis') {
                $client = [HybridAnalysisAPIClient]::new($keyCfg.key, $proxy)
                if ($keyInfo.rpm -and $keyInfo.rph) {
                    $client.SetRateLimits($keyInfo.rpm, $keyInfo.rph)
                }
                $keyInfo.api_client = $client
            }

            $this.Keys += $keyInfo
        }

        # Sort by priority
        $this.Keys = $this.Keys | Sort-Object priority

        Write-Host "[+] Initialized $($this.Keys.Count) API key(s) for $serviceName" -ForegroundColor Green
    }

    [object] GetNextAvailableClient() {
        if ($this.Keys.Count -eq 0) {
            return $null
        }

        for ($attempt = 0; $attempt -lt $this.Keys.Count; $attempt++) {
            $idx = ($this.CurrentIndex + $attempt) % $this.Keys.Count
            $keyInfo = $this.Keys[$idx]

            # Check if rate limited
            if ($keyInfo.rate_limited_until) {
                if ((Get-Date) -lt $keyInfo.rate_limited_until) {
                    continue
                } else {
                    $keyInfo.rate_limited_until = $null
                }
            }

            $client = $keyInfo.api_client
            if ($client -and -not $client.IsRateLimited()) {
                $this.CurrentIndex = ($idx + 1) % $this.Keys.Count
                return $client
            }
        }

        return $null
    }

    [void] MarkRateLimited([object]$apiClient, [int]$durationSeconds) {
        foreach ($keyInfo in $this.Keys) {
            if ($keyInfo.api_client -eq $apiClient) {
                $keyInfo.rate_limited_until = (Get-Date).AddSeconds($durationSeconds)
                Write-Host "[!] $($this.ServiceName) key ($($keyInfo.tier)) rate limited for ${durationSeconds}s" -ForegroundColor Yellow
                break
            }
        }
    }

    [bool] HasAvailableKeys() {
        return $null -ne $this.GetNextAvailableClient()
    }

    [hashtable] LookupHash([string]$fileHash) {
        $client = $this.GetNextAvailableClient()
        if (-not $client) {
            Write-Host "[!] No available $($this.ServiceName) API keys" -ForegroundColor Red
            return $null
        }

        $result = $client.LookupHash($fileHash)

        if ($client.IsRateLimited()) {
            $this.MarkRateLimited($client, 60)
        }

        return $result
    }

    [hashtable] GetStats() {
        $totalRequests = 0
        $remainingQuota = 0
        $activeKeys = 0

        foreach ($keyInfo in $this.Keys) {
            $client = $keyInfo.api_client
            if ($client) {
                if ($this.ServiceName -eq 'virustotal') {
                    $totalRequests += $client.DailyCount
                    $remainingQuota += $client.GetRemainingQuota()
                } elseif ($this.ServiceName -eq 'hybrid_analysis') {
                    $totalRequests += $client.HourlyCount
                    $remainingQuota += $client.GetRemainingQuota()
                }

                if (-not $client.IsRateLimited()) {
                    $activeKeys++
                }
            }
        }

        return @{
            service = $this.ServiceName
            total_keys = $this.Keys.Count
            active_keys = $activeKeys
            total_requests = $totalRequests
            remaining_quota = $remainingQuota
        }
    }
}

#endregion

#region Helper Functions

function Get-SHA256Hash {
    param([byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($Bytes)
    $sha256.Dispose()

    return ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Calculate-CombinedRisk {
    param(
        [hashtable]$VTResult,
        [hashtable]$HAResult
    )

    $vtFound = $VTResult -and $VTResult.found
    $haFound = $HAResult -and $HAResult.found

    if (-not $vtFound -and -not $haFound) {
        return "UNKNOWN"
    }

    $vtMalicious = if ($vtFound) { $VTResult.malicious } else { 0 }
    $vtSuspicious = if ($vtFound) { $VTResult.suspicious } else { 0 }
    $haScore = if ($haFound) { $HAResult.threat_score } else { 0 }

    # HIGH: VT malicious >= 3 OR HA score >= 70
    if ($vtMalicious -ge 3 -or $haScore -ge 70) {
        return "HIGH"
    }

    # MEDIUM: VT malicious > 0 OR HA score >= 40 OR VT suspicious >= 5
    if ($vtMalicious -gt 0 -or $haScore -ge 40 -or $vtSuspicious -ge 5) {
        return "MEDIUM"
    }

    # LOW: VT malicious == 0 AND HA score < 20
    if ($vtMalicious -eq 0 -and $haScore -lt 20) {
        return "LOW"
    }

    return "UNKNOWN"
}

function Test-APIKey {
    param(
        [string]$Service,
        [string]$APIKey
    )

    # EICAR test file hash
    $testHash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    try {
        if ($Service -eq 'VirusTotal') {
            $client = [VirusTotalAPIClient]::new($APIKey, $null)
            $result = $client.LookupHash($testHash)

            if ($result) {
                return @{
                    success = $true
                    message = "VirusTotal API key is valid"
                    tier_info = "$($client.RequestsPerMinute) req/min, $($client.RequestsPerDay) req/day"
                }
            }
        }
        elseif ($Service -eq 'HybridAnalysis') {
            $client = [HybridAnalysisAPIClient]::new($APIKey, $null)
            $result = $client.LookupHash($testHash)

            if ($result) {
                return @{
                    success = $true
                    message = "Hybrid Analysis API key is valid"
                    tier_info = "$($client.RequestsPerMinute) req/min, $($client.RequestsPerHour) req/hour"
                }
            }
        }

        return @{
            success = $false
            message = "API key test failed - invalid response"
        }
    }
    catch {
        return @{
            success = $false
            message = "API key test failed: $_"
        }
    }
}

function Invoke-InteractiveSetup {
    param([ADSConfigManager]$ConfigMgr)

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "Welcome to ADS Scanner with Threat Intelligence" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "No configuration file found. Let's set up your API keys." -ForegroundColor White
    Write-Host ""

    # VirusTotal setup
    $vtConfigure = Read-Host "Configure VirusTotal? (y/n)"
    if ($vtConfigure -eq 'y') {
        while ($true) {
            $vtKey = Read-Host "  Enter VirusTotal API key"
            if ([string]::IsNullOrEmpty($vtKey)) { break }

            $tier = Read-Host "  Tier (free/paid) [free]"
            if ([string]::IsNullOrEmpty($tier)) { $tier = "free" }

            Write-Host "  Testing key..." -NoNewline
            $testResult = Test-APIKey -Service 'VirusTotal' -APIKey $vtKey

            if ($testResult.success) {
                Write-Host " SUCCESS! ($($testResult.tier_info))" -ForegroundColor Green
                $ConfigMgr.AddAPIKey('virustotal', $vtKey, $tier, 1, $true)
            } else {
                Write-Host " FAILED: $($testResult.message)" -ForegroundColor Red
                continue
            }

            $another = Read-Host "  Add another VT key? (y/n)"
            if ($another -ne 'y') { break }
        }
    }

    # Hybrid Analysis setup
    $haConfigure = Read-Host "`nConfigure Hybrid Analysis? (y/n)"
    if ($haConfigure -eq 'y') {
        while ($true) {
            $haKey = Read-Host "  Enter Hybrid Analysis API key"
            if ([string]::IsNullOrEmpty($haKey)) { break }

            Write-Host "  Testing key..." -NoNewline
            $testResult = Test-APIKey -Service 'HybridAnalysis' -APIKey $haKey

            if ($testResult.success) {
                Write-Host " SUCCESS! ($($testResult.tier_info))" -ForegroundColor Green
                $ConfigMgr.AddAPIKey('hybrid_analysis', $haKey, 'free', 1, $true)
            } else {
                Write-Host " FAILED: $($testResult.message)" -ForegroundColor Red
                continue
            }

            $another = Read-Host "  Add another HA key? (y/n)"
            if ($another -ne 'y') { break }
        }
    }

    # Additional settings
    Write-Host "`nAdditional settings:" -ForegroundColor White
    $excludeZone = Read-Host "  Exclude Zone.Identifier streams? (y/n) [y]"
    if ([string]::IsNullOrEmpty($excludeZone)) { $excludeZone = 'y' }
    $ConfigMgr.SetSetting('exclude_zone_identifier', ($excludeZone -eq 'y'))

    $cacheEnabled = Read-Host "  Enable results caching? (y/n) [y]"
    if ([string]::IsNullOrEmpty($cacheEnabled)) { $cacheEnabled = 'y' }
    $ConfigMgr.SetSetting('cache_enabled', ($cacheEnabled -eq 'y'))

    if ($cacheEnabled -eq 'y') {
        $cacheTTL = Read-Host "  Cache TTL (days) [7]"
        if ([string]::IsNullOrEmpty($cacheTTL)) { $cacheTTL = "7" }
        $ConfigMgr.SetSetting('cache_ttl_days', [int]$cacheTTL)
    }

    $proxyUrl = Read-Host "  Proxy URL (or Enter for none)"
    if (-not [string]::IsNullOrEmpty($proxyUrl)) {
        $ConfigMgr.SetSetting('proxy', $proxyUrl)
    }

    Write-Host ""
    Write-Host "[+] Configuration saved to: $($ConfigMgr.ConfigFile)" -ForegroundColor Green
    Write-Host "[+] API keys encrypted using Windows DPAPI (current user only)" -ForegroundColor Green
    Write-Host ""
    Write-Host "[+] Ready to scan! Run with -UseConfig to use saved configuration." -ForegroundColor Green
    Write-Host ""
}

function Invoke-ConfigCLI {
    param(
        [string]$Action,
        [ADSConfigManager]$ConfigMgr,
        [hashtable]$Params
    )

    switch ($Action) {
        'Init' {
            $ConfigMgr.Initialize()
            Write-Host "[+] Configuration initialized at: $($ConfigMgr.ConfigFile)" -ForegroundColor Green
            return $true
        }

        'Add' {
            if (-not $Params.Service -or -not $Params.Key) {
                Write-Host "[!] ERROR: -Service and -Key required for Add action" -ForegroundColor Red
                return $false
            }

            # Normalize service name (convert hyphen to underscore)
            $service = $Params.Service.ToLower().Replace('-', '_')
            $tier = if ($Params.Tier) { $Params.Tier } else { 'Free' }

            Write-Host "[*] Testing $service API key..." -NoNewline
            $testResult = Test-APIKey -Service $Params.Service -APIKey $Params.Key

            if (-not $testResult.success) {
                Write-Host " FAILED: $($testResult.message)" -ForegroundColor Red
                return $false
            }

            Write-Host " SUCCESS! ($($testResult.tier_info))" -ForegroundColor Green

            $ConfigMgr.AddAPIKey($Params.Service.ToLower(), $Params.Key, $tier, 99, $true)
            Write-Host "[+] API key added for $($Params.Service) ($tier tier)" -ForegroundColor Green
            return $true
        }

        'List' {
            $allKeys = @{
                virustotal = $ConfigMgr.ListAPIKeys('virustotal')
                hybrid_analysis = $ConfigMgr.ListAPIKeys('hybrid_analysis')
            }

            $hasKeys = $false
            foreach ($service in $allKeys.Keys) {
                if ($allKeys[$service].Count -gt 0) {
                    $hasKeys = $true
                    Write-Host "`n$($service.ToUpper()):" -ForegroundColor Cyan
                    foreach ($keyInfo in $allKeys[$service]) {
                        Write-Host "  [$($keyInfo.index)] $($keyInfo.key) (tier=$($keyInfo.tier), priority=$($keyInfo.priority), enabled=$($keyInfo.enabled))"
                    }
                }
            }

            if (-not $hasKeys) {
                Write-Host "[*] No API keys configured" -ForegroundColor Yellow
            }

            return $true
        }

        'Remove' {
            if (-not $Params.Service -or $null -eq $Params.Index) {
                Write-Host "[!] ERROR: -Service and -Index required for Remove action" -ForegroundColor Red
                return $false
            }

            $ConfigMgr.RemoveAPIKey($Params.Service.ToLower(), $Params.Index)
            Write-Host "[+] Removed $($Params.Service) key at index $($Params.Index)" -ForegroundColor Green
            return $true
        }

        'Test' {
            if (-not $Params.Service -or -not $Params.Key) {
                Write-Host "[!] ERROR: -Service and -Key required for Test action" -ForegroundColor Red
                return $false
            }

            Write-Host "[*] Testing $($Params.Service) API key..."
            $testResult = Test-APIKey -Service $Params.Service -APIKey $Params.Key

            if ($testResult.success) {
                Write-Host "[+] SUCCESS: $($testResult.message)" -ForegroundColor Green
                Write-Host "[+] Rate limits: $($testResult.tier_info)" -ForegroundColor Green
            } else {
                Write-Host "[!] FAILED: $($testResult.message)" -ForegroundColor Red
            }

            return $testResult.success
        }

        default {
            Write-Host "[!] ERROR: Unknown config action: $Action" -ForegroundColor Red
            Write-Host "[!] Valid actions: Init, Add, List, Remove, Test" -ForegroundColor Yellow
            return $false
        }
    }
}

#endregion

#region Main Execution

# Dot-source additional modules
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
if (Test-Path (Join-Path $scriptPath 'ADSCache.ps1')) {
    . (Join-Path $scriptPath 'ADSCache.ps1')
}
if (Test-Path (Join-Path $scriptPath 'ADSExportFormats.ps1')) {
    . (Join-Path $scriptPath 'ADSExportFormats.ps1')
}

# Initialize configuration manager
$configMgr = [ADSConfigManager]::new()

# Handle configuration CLI mode
if ($ConfigAction) {
    if (-not $configMgr.ConfigExists()) {
        $configMgr.Initialize()
    } else {
        $configMgr.LoadConfig()
    }

    $params = @{
        Service = $Service
        Key = $Key
        Tier = $Tier
        Index = $Index
    }

    $success = Invoke-ConfigCLI -Action $ConfigAction -ConfigMgr $configMgr -Params $params
    exit $(if ($success) { 0 } else { 1 })
}

# Handle interactive setup
if ($InteractiveSetup) {
    if (-not $configMgr.ConfigExists()) {
        $configMgr.Initialize()
    } else {
        $configMgr.LoadConfig()
    }

    Invoke-InteractiveSetup -ConfigMgr $configMgr
    exit 0
}

# Validate path for scanning
if (-not $Path) {
    Write-Host "[!] ERROR: Path argument required for scanning" -ForegroundColor Red
    Write-Host "[!] Use -InteractiveSetup for first-time configuration" -ForegroundColor Yellow
    Write-Host "[!] Use Get-Help for usage information" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path -Path $Path)) {
    Write-Host "[!] ERROR: Path '$Path' does not exist or is not accessible" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "ADS Scanner v2.0 with Multi-Service Threat Intelligence" -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host ""

# Load or create configuration
if (-not $configMgr.ConfigExists()) {
    Write-Host "[!] No configuration file found" -ForegroundColor Yellow

    if ($UseConfig) {
        Write-Host "[!] Run with -InteractiveSetup to create configuration" -ForegroundColor Yellow
        exit 1
    }

    $configMgr.Initialize()
} else {
    $configMgr.LoadConfig()
}

# Determine settings
if ($UseConfig) {
    if (-not $ExcludeZoneIdentifier) {
        $ExcludeZoneIdentifier = $configMgr.GetSetting('exclude_zone_identifier', $false)
    }
    $cacheEnabled = (-not $NoCache) -and $configMgr.GetSetting('cache_enabled', $true)
    $cacheTTLDays = $configMgr.GetSetting('cache_ttl_days', 7)
    if (-not $Proxy) {
        $Proxy = $configMgr.GetSetting('proxy', $null)
    }
    $parallelAPICalls = (-not $NoParallel) -and $configMgr.GetSetting('parallel_api_calls', $true)
} else {
    $cacheEnabled = -not $NoCache
    $cacheTTLDays = 7
    $parallelAPICalls = -not $NoParallel
}

Write-Host "[*] Scanning path: $Path" -ForegroundColor White
Write-Host "[*] Export format: $ExportFormat" -ForegroundColor White
Write-Host "[*] Cache: $(if ($cacheEnabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
Write-Host "[*] Parallel API calls: $(if ($parallelAPICalls) { 'Enabled' } else { 'Disabled' })" -ForegroundColor White
Write-Host ""

# Initialize API key rotators
$vtRotator = $null
$haRotator = $null

if ($UseConfig) {
    if (-not $SkipVirusTotal) {
        $vtKeys = $configMgr.GetAPIKeys('virustotal')
        if ($vtKeys.Count -gt 0) {
            $vtRotator = [APIKeyRotator]::new('virustotal', $vtKeys, $Proxy)
        }
    }

    if (-not $SkipHybridAnalysis) {
        $haKeys = $configMgr.GetAPIKeys('hybrid_analysis')
        if ($haKeys.Count -gt 0) {
            $haRotator = [APIKeyRotator]::new('hybrid_analysis', $haKeys, $Proxy)
        }
    }
} else {
    # Legacy mode - single VT key
    if ($VirusTotalAPIKey -and -not $SkipVirusTotal) {
        $vtKeys = @(
            @{
                key = $VirusTotalAPIKey
                tier = 'Free'
                priority = 1
                requests_per_minute = 4
                requests_per_day = 500
                enabled = $true
            }
        )
        $vtRotator = [APIKeyRotator]::new('virustotal', $vtKeys, $Proxy)
    }
}

if (-not $vtRotator -and -not $haRotator) {
    Write-Host "[!] WARNING: No API keys configured" -ForegroundColor Yellow
    Write-Host "[!] Scanning will collect hashes but no threat intelligence lookups will be performed" -ForegroundColor Yellow
    Write-Host "[!] Run with -InteractiveSetup to configure API keys" -ForegroundColor Yellow
    Write-Host ""
}

# Initialize cache manager
$cacheManager = $null
if ($cacheEnabled) {
    try {
        $cacheManager = [ADSCacheManager]::new($configMgr.CacheDir, $cacheTTLDays, $true)
        $cacheManager.PruneExpired()
        Write-Verbose "Cache manager initialized"
    } catch {
        Write-Warning "Failed to initialize cache manager: $_"
        $cacheManager = $null
    }
}

# Set output file
if (-not $OutputFile) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ext = $ExportFormat.ToLower()
    $OutputFile = "ADS_Report_${timestamp}.$ext"
}

Write-Host "[*] Output file: $OutputFile" -ForegroundColor White
Write-Host ""

# Load resume data
$resumeHashes = @{}
if ($ResumeFile -and (Test-Path $ResumeFile)) {
    Write-Host "[*] Loading resume file: $ResumeFile" -ForegroundColor Cyan
    $resumeData = Import-Csv $ResumeFile
    foreach ($row in $resumeData) {
        if ($row.StreamSHA256) {
            $resumeHashes[$row.StreamSHA256] = $true
        }
    }
    Write-Host "[+] Loaded $($resumeHashes.Count) previously scanned hashes" -ForegroundColor Green
    Write-Host ""
}

# Scan files
$results = @()
$fileCount = 0
$adsCount = 0
$stats = @{
    vt_not_found = 0
    vt_malicious = 0
    ha_malicious = 0
    high_risk = 0
    medium_risk = 0
    low_risk = 0
    unknown_risk = 0
}

Write-Host "[*] Starting scan..." -ForegroundColor Cyan
Write-Host ("=" * 70) -ForegroundColor Cyan

$files = Get-ChildItem -Path $Path -File -Recurse -ErrorAction SilentlyContinue
$totalFiles = $files.Count

foreach ($file in $files) {
    $fileCount++

    if ($fileCount % 100 -eq 0) {
        $percentComplete = [math]::Round(($fileCount / $totalFiles) * 100, 2)
        Write-Progress -Activity "Scanning for ADS" -Status "$fileCount of $totalFiles files scanned ($adsCount ADS found, $($stats.high_risk) high risk)" -PercentComplete $percentComplete
    }

    try {
        $streams = Get-Item -Path $file.FullName -Stream * -ErrorAction SilentlyContinue
        $alternateStreams = $streams | Where-Object { $_.Stream -ne ':$DATA' }

        foreach ($stream in $alternateStreams) {
            if ($ExcludeZoneIdentifier -and $stream.Stream -eq 'Zone.Identifier') {
                continue
            }

            $adsCount++

            # Read stream and compute hash
            $streamPath = "$($file.FullName):$($stream.Stream)"
            $streamBytes = $null
            $streamHash = ""
            $streamType = "Unknown"
            $streamContent = ""

            try {
                $streamBytes = Get-Content -Path $streamPath -Encoding Byte -Raw -ErrorAction SilentlyContinue

                if ($streamBytes) {
                    $streamHash = Get-SHA256Hash -Bytes $streamBytes

                    # Skip if in resume hashes
                    if ($resumeHashes.ContainsKey($streamHash)) {
                        continue
                    }

                    # Determine content type
                    $isText = $true
                    $previewBytes = $streamBytes[0..[Math]::Min(100, $streamBytes.Length - 1)]
                    foreach ($byte in $previewBytes) {
                        if ($byte -eq 0 -or ($byte -lt 32 -and $byte -ne 9 -and $byte -ne 10 -and $byte -ne 13)) {
                            $isText = $false
                            break
                        }
                    }

                    if ($isText) {
                        $streamType = "Text"
                        $streamContent = [System.Text.Encoding]::ASCII.GetString($previewBytes)
                    } else {
                        $streamType = "Binary"
                        $streamContent = ($previewBytes | ForEach-Object { $_.ToString("X2") }) -join " "
                    }
                }
            } catch {
                $streamContent = "Unable to read"
            }

            # API lookups
            $vtResult = $null
            $haResult = $null
            $apiKeysUsed = @()
            $fromCache = $false

            if ($streamHash -and ($vtRotator -or $haRotator)) {
                Write-Host "[$adsCount] Checking: $($file.Name):$($stream.Stream)" -ForegroundColor Cyan
                Write-Host "    SHA256: $streamHash"

                # Check cache first
                if ($cacheManager -and $cacheManager.HasResult($streamHash)) {
                    $cached = $cacheManager.GetResult($streamHash)
                    $vtResult = $cached.vt
                    $haResult = $cached.ha
                    $fromCache = $true
                    Write-Host "    [CACHE] Results from cache" -ForegroundColor Cyan
                } else {
                    # Query APIs
                    if ($vtRotator) {
                        $vtResult = $vtRotator.LookupHash($streamHash)
                        if ($vtResult) {
                            $apiKeysUsed += "VT"
                        }
                    }

                    if ($haRotator) {
                        $haResult = $haRotator.LookupHash($streamHash)
                        if ($haResult) {
                            $apiKeysUsed += "HA"
                        }
                    }

                    # Store in cache
                    if ($cacheManager -and ($vtResult -or $haResult)) {
                        $cacheManager.StoreResult($streamHash, $vtResult, $haResult)
                    }
                }

                # Display results
                if ($vtResult) {
                    if (-not $vtResult.found) {
                        $stats.vt_not_found++
                        Write-Host "    [VT] NOT IN DATABASE" -ForegroundColor Magenta
                    } elseif ($vtResult.malicious -gt 0) {
                        $stats.vt_malicious++
                        Write-Host "    [VT] MALICIOUS: $($vtResult.detection_ratio)" -ForegroundColor Red
                    } else {
                        Write-Host "    [VT] Clean: $($vtResult.detection_ratio)" -ForegroundColor Green
                    }
                }

                if ($haResult) {
                    if (-not $haResult.found) {
                        Write-Host "    [HA] NOT IN DATABASE" -ForegroundColor Magenta
                    } elseif ($haResult.threat_score -ge 70) {
                        $stats.ha_malicious++
                        Write-Host "    [HA] MALICIOUS: Score $($haResult.threat_score) ($($haResult.verdict))" -ForegroundColor Red
                    } elseif ($haResult.threat_score -ge 40) {
                        Write-Host "    [HA] SUSPICIOUS: Score $($haResult.threat_score) ($($haResult.verdict))" -ForegroundColor Yellow
                    } else {
                        Write-Host "    [HA] Clean: Score $($haResult.threat_score)" -ForegroundColor Green
                    }
                }

                # Calculate combined risk
                $combinedRisk = Calculate-CombinedRisk -VTResult $vtResult -HAResult $haResult
                $stats["$($combinedRisk.ToLower())_risk"]++

                if ($combinedRisk -eq "HIGH") {
                    Write-Host "    [!!!] COMBINED RISK: HIGH" -ForegroundColor Red
                } elseif ($combinedRisk -eq "MEDIUM") {
                    Write-Host "    [!] COMBINED RISK: MEDIUM" -ForegroundColor Yellow
                }
            }

            # Build result object
            $result = [PSCustomObject]@{
                FilePath = $file.FullName
                FileName = $file.Name
                FileSize = $file.Length
                FileExtension = $file.Extension
                FileCreated = $file.CreationTime
                FileModified = $file.LastWriteTime
                FileAccessed = $file.LastAccessTime
                StreamName = $stream.Stream
                StreamSize = $stream.Length
                StreamType = $streamType
                StreamSHA256 = $streamHash
                StreamPreview = $streamContent.Substring(0, [Math]::Min(200, $streamContent.Length))

                # VirusTotal
                VT_Found = if ($vtResult) { $vtResult.found } else { "N/A" }
                VT_DetectionRatio = if ($vtResult) { $vtResult.detection_ratio } else { "N/A" }
                VT_Malicious = if ($vtResult) { $vtResult.malicious } else { "N/A" }
                VT_Suspicious = if ($vtResult) { $vtResult.suspicious } else { "N/A" }
                VT_Undetected = if ($vtResult) { $vtResult.undetected } else { "N/A" }
                VT_Harmless = if ($vtResult) { $vtResult.harmless } else { "N/A" }
                VT_DetectionEngines = if ($vtResult) { $vtResult.detection_engines } else { "N/A" }
                VT_ScanDate = if ($vtResult) { $vtResult.scan_date } else { "N/A" }
                VT_Link = if ($vtResult) { $vtResult.link } else { "N/A" }

                # Hybrid Analysis
                HA_Found = if ($haResult) { $haResult.found } else { "N/A" }
                HA_ThreatScore = if ($haResult) { $haResult.threat_score } else { "N/A" }
                HA_Verdict = if ($haResult) { $haResult.verdict } else { "N/A" }
                HA_AVDetect = if ($haResult) { $haResult.av_detect } else { "N/A" }
                HA_VXFamily = if ($haResult) { $haResult.vx_family } else { "N/A" }
                HA_JobID = if ($haResult) { $haResult.job_id } else { "N/A" }
                HA_ReportURL = if ($haResult) { $haResult.report_url } else { "N/A" }
                HA_ScanDate = if ($haResult) { $haResult.scan_date } else { "N/A" }

                # Combined
                Combined_Risk = if ($vtResult -or $haResult) { $combinedRisk } else { "UNKNOWN" }
                FlagForSubmission = if (($vtResult -and -not $vtResult.found) -or ($haResult -and -not $haResult.found)) { "YES" } else { "NO" }

                # Metadata
                CachedResult = if ($fromCache) { "YES" } else { "NO" }
                APIKeysUsed = ($apiKeysUsed -join ",")
                ScanDate = Get-Date
            }

            $results += $result

            # Save progress every 10 results
            if ($results.Count % 10 -eq 0 -and $ExportFormat -eq 'CSV') {
                $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
            }
        }
    } catch {
        Write-Verbose "Error scanning $($file.FullName): $_"
    }
}

Write-Progress -Activity "Scanning for ADS" -Completed

Write-Host ""
Write-Host "[+] Scan complete: $fileCount files, $adsCount ADS found" -ForegroundColor Green
Write-Host "[+] Risk summary: $($stats.high_risk) HIGH, $($stats.medium_risk) MEDIUM, $($stats.low_risk) LOW, $($stats.unknown_risk) UNKNOWN" -ForegroundColor Green
Write-Host ""

# Save cache if enabled
if ($cacheManager) {
    $cacheManager.SaveCache()
}

# Export results
if ($results.Count -gt 0) {
    # Prepare scan metadata
    $scanMetadata = @{
        scan_date = (Get-Date).ToString('o')
        scan_path = $Path
        api_usage = @{}
        cache_stats = if ($cacheManager) { $cacheManager.GetStats() } else { @{} }
    }

    if ($vtRotator) {
        $scanMetadata.api_usage['virustotal'] = $vtRotator.GetStats()
    }
    if ($haRotator) {
        $scanMetadata.api_usage['hybrid_analysis'] = $haRotator.GetStats()
    }

    # Export based on format
    switch ($ExportFormat) {
        'CSV' {
            $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        }
        'JSON' {
            if (Get-Command Export-ADSToJSON -ErrorAction SilentlyContinue) {
                Export-ADSToJSON -Results $results -OutputPath $OutputFile -ScanMetadata $scanMetadata
            } else {
                Write-Warning "JSON export not available - falling back to CSV"
                $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
            }
        }
        'HTML' {
            if (Get-Command Export-ADSToHTML -ErrorAction SilentlyContinue) {
                Export-ADSToHTML -Results $results -OutputPath $OutputFile -ScanMetadata $scanMetadata
            } else {
                Write-Warning "HTML export not available - falling back to CSV"
                $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
            }
        }
        'STIX' {
            if (Get-Command Export-ADSToSTIX -ErrorAction SilentlyContinue) {
                Export-ADSToSTIX -Results $results -OutputPath $OutputFile -ScanMetadata $scanMetadata
            } else {
                Write-Warning "STIX export not available - falling back to CSV"
                $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
            }
        }
    }

    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "Scan Complete!" -ForegroundColor Green
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "ADS streams found:   $($results.Count)" -ForegroundColor White
    Write-Host "Report saved to:     $OutputFile" -ForegroundColor White

    if ($vtRotator -or $haRotator) {
        Write-Host ""
        Write-Host "Threat Intelligence Summary:" -ForegroundColor Cyan

        if ($vtRotator) {
            $vtStats = $vtRotator.GetStats()
            Write-Host "  VirusTotal requests:   $($vtStats.total_requests)" -ForegroundColor White
            Write-Host "  VT keys used:          $($vtStats.total_keys)" -ForegroundColor White
        }

        if ($haRotator) {
            $haStats = $haRotator.GetStats()
            Write-Host "  Hybrid Analysis requests: $($haStats.total_requests)" -ForegroundColor White
            Write-Host "  HA keys used:          $($haStats.total_keys)" -ForegroundColor White
        }
    }

    if ($cacheManager) {
        $cacheStats = $cacheManager.GetStats()
        Write-Host ""
        Write-Host "Cache Performance:" -ForegroundColor Cyan
        Write-Host "  Cache hits:    $($cacheStats.cache_hits)" -ForegroundColor White
        Write-Host "  Cache misses:  $($cacheStats.cache_misses)" -ForegroundColor White
        Write-Host "  Hit rate:      $($cacheStats.hit_rate)" -ForegroundColor White
    }

    # Show high risk findings
    $highRisk = $results | Where-Object { $_.Combined_Risk -eq "HIGH" }
    if ($highRisk) {
        Write-Host ""
        Write-Host "[!!!] $($highRisk.Count) HIGH RISK stream(s) detected:" -ForegroundColor Red
        foreach ($r in $highRisk | Select-Object -First 10) {
            Write-Host "    - $($r.FileName):$($r.StreamName)" -ForegroundColor Red
            if ($r.VT_Link -ne 'N/A') {
                Write-Host "      VT: $($r.VT_Link)" -ForegroundColor Gray
            }
            if ($r.HA_ReportURL -ne 'N/A') {
                Write-Host "      HA: $($r.HA_ReportURL)" -ForegroundColor Gray
            }
        }
    }

    Write-Host ("=" * 70) -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "Scan Complete!" -ForegroundColor Green
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "Files scanned:       $fileCount" -ForegroundColor White
    Write-Host "ADS streams found:   0" -ForegroundColor Yellow
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "No alternate data streams found in the scanned path." -ForegroundColor Yellow
}

#endregion
