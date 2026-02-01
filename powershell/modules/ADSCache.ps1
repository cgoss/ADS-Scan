<#
.SYNOPSIS
    Cache Manager for ADS Scanner (PowerShell Module)

.DESCRIPTION
    File-based caching system for API results with TTL expiration
    Can be dot-sourced into main script or used independently
#>

class ADSCacheManager {
    [string]$CacheDir
    [string]$CacheFile
    [int]$TTLDays
    [bool]$Enabled
    [int]$CacheHits = 0
    [int]$CacheMisses = 0
    [hashtable]$Cache

    ADSCacheManager([string]$cacheDir, [int]$ttlDays, [bool]$enabled) {
        $this.CacheDir = $cacheDir
        $this.CacheFile = Join-Path $cacheDir 'results_cache.json'
        $this.TTLDays = $ttlDays
        $this.Enabled = $enabled
        $this.Cache = @{}

        if ($this.Enabled) {
            if (-not (Test-Path $this.CacheDir)) {
                New-Item -Path $this.CacheDir -ItemType Directory -Force | Out-Null
            }
            $this.LoadCache()
        }
    }

    [void] LoadCache() {
        if (Test-Path $this.CacheFile) {
            try {
                $json = Get-Content -Path $this.CacheFile -Raw
                $this.Cache = $json | ConvertFrom-Json -AsHashtable
            } catch {
                Write-Warning "Failed to load cache file: $_"
                $this.Cache = @{}
            }
        }
    }

    [void] SaveCache() {
        if (-not $this.Enabled) { return }

        try {
            $json = $this.Cache | ConvertTo-Json -Depth 10
            $json | Set-Content -Path $this.CacheFile -Encoding UTF8
        } catch {
            Write-Warning "Failed to save cache file: $_"
        }
    }

    [bool] HasResult([string]$fileHash) {
        if (-not $this.Enabled) { return $false }

        if (-not $this.Cache.ContainsKey($fileHash)) {
            return $false
        }

        $entry = $this.Cache[$fileHash]
        $expiresAt = [datetime]::Parse($entry.expires_at)

        return (Get-Date) -lt $expiresAt
    }

    [hashtable] GetResult([string]$fileHash) {
        if (-not $this.Enabled) {
            $this.CacheMisses++
            return $null
        }

        if (-not $this.HasResult($fileHash)) {
            $this.CacheMisses++
            return $null
        }

        $this.CacheHits++
        $entry = $this.Cache[$fileHash]

        return @{
            vt = $entry.vt_result
            ha = $entry.ha_result
            cached_at = $entry.cached_at
            from_cache = $true
        }
    }

    [void] StoreResult([string]$fileHash, [hashtable]$vtResult, [hashtable]$haResult) {
        if (-not $this.Enabled) { return }

        $cachedAt = Get-Date
        $expiresAt = $cachedAt.AddDays($this.TTLDays)

        $this.Cache[$fileHash] = @{
            vt_result = $vtResult
            ha_result = $haResult
            cached_at = $cachedAt.ToString('o')
            expires_at = $expiresAt.ToString('o')
        }

        # Save every 10 entries
        if ($this.Cache.Count % 10 -eq 0) {
            $this.SaveCache()
        }
    }

    [void] PruneExpired() {
        if (-not $this.Enabled) { return }

        $now = Get-Date
        $toRemove = @()

        foreach ($hash in $this.Cache.Keys) {
            $entry = $this.Cache[$hash]
            $expiresAt = [datetime]::Parse($entry.expires_at)

            if ($now -gt $expiresAt) {
                $toRemove += $hash
            }
        }

        foreach ($hash in $toRemove) {
            $this.Cache.Remove($hash)
        }

        if ($toRemove.Count -gt 0) {
            Write-Verbose "Pruned $($toRemove.Count) expired cache entries"
            $this.SaveCache()
        }
    }

    [hashtable] GetStats() {
        $totalEntries = $this.Cache.Count
        $totalRequests = $this.CacheHits + $this.CacheMisses
        $hitRate = if ($totalRequests -gt 0) {
            [math]::Round(($this.CacheHits / $totalRequests) * 100, 1)
        } else { 0 }

        return @{
            enabled = $this.Enabled
            total_entries = $totalEntries
            cache_hits = $this.CacheHits
            cache_misses = $this.CacheMisses
            hit_rate = "${hitRate}%"
            ttl_days = $this.TTLDays
        }
    }

    [void] Clear() {
        $this.Cache = @{}
        $this.CacheHits = 0
        $this.CacheMisses = 0

        if (Test-Path $this.CacheFile) {
            Remove-Item -Path $this.CacheFile -Force
        }
    }
}

# Export for dot-sourcing
Export-ModuleMember -Function * -Variable *
