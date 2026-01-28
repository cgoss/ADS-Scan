<#
.SYNOPSIS
    ADS Scanner - API Key Management Interface (Pure PowerShell)
    Provides a user-friendly interface to view, add, update, and remove API keys

.DESCRIPTION
    This script provides a menu-driven interface for managing API keys for the ADS Scanner.
    It allows users to view, add, update, remove, and test API keys for VirusTotal and Hybrid Analysis.
    This is a pure PowerShell version that doesn't require C# code compilation.
#>

#requires -Version 5.1

# Define configuration paths
$localAppData = [Environment]::GetFolderPath('LocalApplicationData')
$configDir = Join-Path $localAppData 'ADSScanner'
$configFile = Join-Path $configDir 'config.json'
$cacheDir = Join-Path $configDir 'cache'
$logDir = Join-Path $configDir 'logs'

function Show-APIKeyMenu {
    Clear-Host
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "           ADS Scanner - API Key Manager" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""
}

function Show-MenuOptions {
    Write-Host "API Key Management Menu:" -ForegroundColor Yellow
    Write-Host "1. View configured API keys"
    Write-Host "2. Add a new API key"
    Write-Host "3. Update an existing API key"
    Write-Host "4. Remove an API key"
    Write-Host "5. Test an API key"
    Write-Host "6. Exit"
    Write-Host ""
}

function Initialize-Config {
    if (!(Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    if (!(Test-Path $cacheDir)) {
        New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null
    }
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }

    if (!(Test-Path $configFile)) {
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

        $defaultConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
    }
}

function Load-Config {
    if (Test-Path $configFile) {
        $content = Get-Content -Path $configFile -Raw -Encoding UTF8
        return $content | ConvertFrom-Json
    }
    return $null
}

function Save-Config {
    param([object]$config)
    
    $config | ConvertTo-Json -Depth 10 | Set-Content -Path $configFile -Encoding UTF8
}

function Show-APIKeys {
    param([object]$config)
    
    Write-Host "`nConfigured API Keys:" -ForegroundColor Green
    Write-Host "-" * 80
    
    try {
        $allKeys = @{
            virustotal = @()
            hybrid_analysis = @()
        }
        
        # List API keys with masking
        if ($config.api_keys.virustotal) {
            for ($i = 0; $i -lt $config.api_keys.virustotal.Count; $i++) {
                $key = $config.api_keys.virustotal[$i]
                $maskedKey = $key.PSObject.Copy()
                $maskedKey.key = "***" + $key.key.Substring([Math]::Max(0, $key.key.Length - 8))
                $maskedKey | Add-Member -NotePropertyName "index" -NotePropertyValue $i
                $allKeys.virustotal += $maskedKey
            }
        }
        
        if ($config.api_keys.hybrid_analysis) {
            for ($i = 0; $i -lt $config.api_keys.hybrid_analysis.Count; $i++) {
                $key = $config.api_keys.hybrid_analysis[$i]
                $maskedKey = $key.PSObject.Copy()
                $maskedKey.key = "***" + $key.key.Substring([Math]::Max(0, $key.key.Length - 8))
                $maskedKey | Add-Member -NotePropertyName "index" -NotePropertyValue $i
                $allKeys.hybrid_analysis += $maskedKey
            }
        }
        
        $hasKeys = $false
        
        if ($allKeys.virustotal.Count -gt 0) {
            Write-Host ""
            Write-Host "VIRUSTOTAL:" -ForegroundColor Cyan
            foreach ($keyInfo in $allKeys.virustotal) {
                $status = if ($keyInfo.enabled) { "ENABLED" } else { "DISABLED" }
                Write-Host "  [$($keyInfo.index)] $($keyInfo.key) " -NoNewline
                Write-Host "(Tier: $($keyInfo.tier), Priority: $($keyInfo.priority), Status: $status)"
            }
            $hasKeys = $true
        }
        
        if ($allKeys.hybrid_analysis.Count -gt 0) {
            Write-Host ""
            Write-Host "HYBRID ANALYSIS:" -ForegroundColor Cyan
            foreach ($keyInfo in $allKeys.hybrid_analysis) {
                $status = if ($keyInfo.enabled) { "ENABLED" } else { "DISABLED" }
                Write-Host "  [$($keyInfo.index)] $($keyInfo.key) " -NoNewline
                Write-Host "(Tier: $($keyInfo.tier), Priority: $($keyInfo.priority), Status: $status)"
            }
            $hasKeys = $true
        }
        
        if (-not $hasKeys) {
            Write-Host "  No API keys configured." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error displaying API keys: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "-" * 80
}

function Test-APIKeyLocally {
    param(
        [string]$Service,
        [string]$APIKey
    )

    # This is a simplified test - in reality, you'd make an actual API call
    # For demo purposes, we'll just validate the key format
    if ([string]::IsNullOrWhiteSpace($APIKey)) {
        return @{
            success = $false
            message = "API key cannot be empty"
        }
    }

    # Basic validation - API keys are usually long alphanumeric strings
    if ($APIKey.Length -lt 10) {
        return @{
            success = $false
            message = "API key appears to be too short"
        }
    }

    # For a real implementation, you would make an actual API call here
    return @{
        success = $true
        message = "$Service API key format appears valid"
        tier_info = "Rate limits would be shown here"
    }
}

function Add-APIKey {
    param([object]$config)
    
    Write-Host ""
    Write-Host "Add New API Key" -ForegroundColor Green
    Write-Host "-" * 30
    
    # Get service
    Write-Host "Select service:"
    Write-Host "1. VirusTotal"
    Write-Host "2. Hybrid Analysis"
    
    do {
        $serviceChoice = Read-Host "Enter choice (1-2)"
        switch ($serviceChoice) {
            '1' { 
                $service = 'virustotal'
                $serviceName = 'VirusTotal'
                break
            }
            '2' { 
                $service = 'hybrid_analysis'
                $serviceName = 'Hybrid Analysis'
                break
            }
            default { 
                Write-Host "Invalid choice. Please enter 1 or 2." -ForegroundColor Red
            }
        }
    } while (-not $service)
    
    # Get API key
    $apiKey = Read-Host "`nEnter $serviceName API key"
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        Write-Host "API key cannot be empty." -ForegroundColor Red
        return
    }
    
    # Get tier for VirusTotal
    $tier = 'free'
    if ($service -eq 'virustotal') {
        do {
            $tierInput = Read-Host "Enter tier (free/paid) [free]"
            if ([string]::IsNullOrWhiteSpace($tierInput)) {
                $tier = 'free'
                break
            }
            elseif ($tierInput -in @('free', 'paid')) {
                $tier = $tierInput
                break
            }
            else {
                Write-Host "Invalid tier. Please enter 'free' or 'paid'." -ForegroundColor Red
            }
        } while ($true)
    }
    
    # Get priority
    do {
        try {
            $priorityInput = Read-Host "Enter priority (1-99, lower = higher priority) [99]"
            if ([string]::IsNullOrWhiteSpace($priorityInput)) {
                $priority = 99
                break
            }
            $priority = [int]$priorityInput
            if ($priority -ge 1 -and $priority -le 99) {
                break
            }
            else {
                Write-Host "Priority must be between 1 and 99." -ForegroundColor Red
            }
        }
        catch {
            Write-Host "Please enter a valid number." -ForegroundColor Red
        }
    } while ($true)
    
    # Set default rate limits
    $keyConfig = @{
        key = $apiKey  # In real implementation, this would be encrypted
        tier = $tier
        enabled = $true
        priority = $priority
    }
    
    if ($service -eq 'virustotal') {
        if ($tier -eq 'free') {
            $keyConfig.requests_per_minute = 4
            $keyConfig.requests_per_day = 500
        }
        else {
            $keyConfig.requests_per_minute = 1000
            $keyConfig.requests_per_day = 300000
        }
    }
    elseif ($service -eq 'hybrid_analysis') {
        $keyConfig.requests_per_minute = 5
        $keyConfig.requests_per_hour = 200
    }
    
    # Test the API key before adding
    Write-Host "`nTesting $serviceName API key..." -NoNewline
    $testResult = Test-APIKeyLocally -Service $serviceName -APIKey $apiKey
    
    if ($testResult.success) {
        Write-Host " SUCCESS!" -ForegroundColor Green
        Write-Host "($($testResult.tier_info))"
        
        # Add the key to config
        $config.api_keys.$service += $keyConfig
        
        # Sort by priority
        $sortedKeys = $config.api_keys.$service | Sort-Object priority
        $config.api_keys.$service = $sortedKeys
        
        # Save config
        Save-Config -config $config
        
        Write-Host "`n[SUCCESS] API key added successfully for $serviceName!" -ForegroundColor Green
        
        # Show updated list
        Show-APIKeys -config $config
    }
    else {
        Write-Host " FAILED!" -ForegroundColor Red
        Write-Host "$($testResult.message)"
        Write-Host "API key was not added." -ForegroundColor Yellow
    }
}

function Update-APIKey {
    param([object]$config)
    
    Write-Host ""
    Write-Host "Update Existing API Key" -ForegroundColor Green
    Write-Host "-" * 30
    
    # First, show current keys
    Show-APIKeys -config $config
    
    # Get service
    Write-Host "`nSelect service:"
    Write-Host "1. VirusTotal"
    Write-Host "2. Hybrid Analysis"
    
    do {
        $serviceChoice = Read-Host "Enter choice (1-2)"
        switch ($serviceChoice) {
            '1' { 
                $service = 'virustotal'
                $serviceName = 'VirusTotal'
                break
            }
            '2' { 
                $service = 'hybrid_analysis'
                $serviceName = 'Hybrid Analysis'
                break
            }
            default { 
                Write-Host "Invalid choice. Please enter 1 or 2." -ForegroundColor Red
            }
        }
    } while (-not $service)
    
    # Get current keys for the service
    $keys = $config.api_keys.$service
    if ($keys.Count -eq 0) {
        Write-Host "`nNo $serviceName keys configured." -ForegroundColor Yellow
        return
    }
    
    # Show available keys
    Write-Host "`nAvailable $serviceName keys:"
    for ($i = 0; $i -lt $keys.Count; $i++) {
        $key = $keys[$i]
        $status = if ($key.enabled) { "ENABLED" } else { "DISABLED" }
        $maskedKey = "***" + $key.key.Substring([Math]::Max(0, $key.key.Length - 8))
        Write-Host "  [$i] $maskedKey " -NoNewline
        Write-Host "(Tier: $($key.tier), Priority: $($key.priority), Status: $status)"
    }
    
    # Get key index to update
    do {
        try {
            $maxIndex = $keys.Count - 1
            $indexInput = Read-Host "`nEnter the index of the key to update (0-$maxIndex)"
            $index = [int]$indexInput
            if ($index -ge 0 -and $index -le $maxIndex) {
                break
            }
            else {
                Write-Host "Invalid index. Please enter a number between 0 and $maxIndex." -ForegroundColor Red
            }
        }
        catch {
            Write-Host "Please enter a valid number." -ForegroundColor Red
        }
    } while ($true)
    
    # Get existing key info for defaults
    $existingKey = $keys[$index]
    
    # Get new API key
    $newApiKey = Read-Host "`nEnter new $serviceName API key"
    if ([string]::IsNullOrWhiteSpace($newApiKey)) {
        Write-Host "API key cannot be empty." -ForegroundColor Red
        return
    }
    
    # Get new tier for VirusTotal
    $tier = $existingKey.tier  # Default to existing tier
    if ($service -eq 'virustotal') {
        do {
            $tierInput = Read-Host "Enter new tier (free/paid) [$($existingKey.tier)]"
            if ([string]::IsNullOrWhiteSpace($tierInput)) {
                break  # Keep existing tier
            }
            elseif ($tierInput -in @('free', 'paid')) {
                $tier = $tierInput
                break
            }
            else {
                Write-Host "Invalid tier. Please enter 'free' or 'paid'." -ForegroundColor Red
            }
        } while ($true)
    }
    
    # Get new priority
    $priority = $existingKey.priority  # Default to existing priority
    do {
        try {
            $priorityInput = Read-Host "Enter new priority (1-99) [$($existingKey.priority)]"
            if ([string]::IsNullOrWhiteSpace($priorityInput)) {
                break  # Keep existing priority
            }
            $priority = [int]$priorityInput
            if ($priority -ge 1 -and $priority -le 99) {
                break
            }
            else {
                Write-Host "Priority must be between 1 and 99." -ForegroundColor Red
            }
        }
        catch {
            Write-Host "Please enter a valid number." -ForegroundColor Red
        }
    } while ($true)
    
    # Set updated key config
    $updatedKeyConfig = @{
        key = $newApiKey  # In real implementation, this would be encrypted
        tier = $tier
        enabled = $true
        priority = $priority
    }
    
    if ($service -eq 'virustotal') {
        if ($tier -eq 'free') {
            $updatedKeyConfig.requests_per_minute = 4
            $updatedKeyConfig.requests_per_day = 500
        }
        else {
            $updatedKeyConfig.requests_per_minute = 1000
            $updatedKeyConfig.requests_per_day = 300000
        }
    }
    elseif ($service -eq 'hybrid_analysis') {
        $updatedKeyConfig.requests_per_minute = 5
        $updatedKeyConfig.requests_per_hour = 200
    }
    
    # Test the new API key before updating
    Write-Host "`nTesting new $serviceName API key..." -NoNewline
    $testResult = Test-APIKeyLocally -Service $serviceName -APIKey $newApiKey
    
    if ($testResult.success) {
        Write-Host " SUCCESS!" -ForegroundColor Green
        Write-Host "($($testResult.tier_info))"
        
        # Replace the key in config
        $config.api_keys.$service[$index] = $updatedKeyConfig
        
        # Sort by priority
        $sortedKeys = $config.api_keys.$service | Sort-Object priority
        $config.api_keys.$service = $sortedKeys
        
        # Save config
        Save-Config -config $config
        
        Write-Host "`n[SUCCESS] API key updated successfully for $serviceName!" -ForegroundColor Green
        
        # Show updated list
        Show-APIKeys -config $config
    }
    else {
        Write-Host " FAILED!" -ForegroundColor Red
        Write-Host "$($testResult.message)"
        Write-Host "API key was not updated." -ForegroundColor Yellow
    }
}

function Remove-APIKey {
    param([object]$config)
    
    Write-Host ""
    Write-Host "Remove API Key" -ForegroundColor Green
    Write-Host "-" * 20
    
    # First, show current keys
    Show-APIKeys -config $config
    
    # Get service
    Write-Host "`nSelect service:"
    Write-Host "1. VirusTotal"
    Write-Host "2. Hybrid Analysis"
    
    do {
        $serviceChoice = Read-Host "Enter choice (1-2)"
        switch ($serviceChoice) {
            '1' { 
                $service = 'virustotal'
                $serviceName = 'VirusTotal'
                break
            }
            '2' { 
                $service = 'hybrid_analysis'
                $serviceName = 'Hybrid Analysis'
                break
            }
            default { 
                Write-Host "Invalid choice. Please enter 1 or 2." -ForegroundColor Red
            }
        }
    } while (-not $service)
    
    # Get current keys for the service
    $keys = $config.api_keys.$service
    if ($keys.Count -eq 0) {
        Write-Host "`nNo $serviceName keys configured." -ForegroundColor Yellow
        return
    }
    
    # Show available keys
    Write-Host "`nAvailable $serviceName keys:"
    for ($i = 0; $i -lt $keys.Count; $i++) {
        $key = $keys[$i]
        $status = if ($key.enabled) { "ENABLED" } else { "DISABLED" }
        $maskedKey = "***" + $key.key.Substring([Math]::Max(0, $key.key.Length - 8))
        Write-Host "  [$i] $maskedKey " -NoNewline
        Write-Host "(Tier: $($key.tier), Priority: $($key.priority), Status: $status)"
    }
    
    # Get key index to remove
    $maxIndex = $keys.Count - 1
    do {
        try {
            $indexInput = Read-Host "`nEnter the index of the key to remove (0-$maxIndex)"
            $index = [int]$indexInput
            if ($index -ge 0 -and $index -le $maxIndex) {
                break
            }
            else {
                Write-Host "Invalid index. Please enter a number between 0 and $maxIndex." -ForegroundColor Red
            }
        }
        catch {
            Write-Host "Please enter a valid number." -ForegroundColor Red
        }
    } while ($true)
    
    # Confirm removal
    $confirm = Read-Host "`nAre you sure you want to remove key [$index]? (yes/no)"
    if ($confirm -in @('yes', 'y', 'Y', 'YES')) {
        try {
            # Remove the key from config
            $newKeys = @()
            for ($i = 0; $i -lt $keys.Count; $i++) {
                if ($i -ne $index) {
                    $newKeys += $keys[$i]
                }
            }
            $config.api_keys.$service = $newKeys
            
            # Save config
            Save-Config -config $config
            
            Write-Host "`n[SUCCESS] API key removed successfully from $serviceName!" -ForegroundColor Green
            
            # Show updated list
            Show-APIKeys -config $config
        }
        catch {
            Write-Host "`n[ERROR] Error removing API key: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "Removal cancelled." -ForegroundColor Yellow
    }
}

function Test-APIKeyInteractive {
    param([object]$config)
    
    Write-Host ""
    Write-Host "Test API Key" -ForegroundColor Green
    Write-Host "-" * 15
    
    # Get service
    Write-Host "Select service:"
    Write-Host "1. VirusTotal"
    Write-Host "2. Hybrid Analysis"
    
    do {
        $serviceChoice = Read-Host "Enter choice (1-2)"
        switch ($serviceChoice) {
            '1' { 
                $service = 'VirusTotal'
                break
            }
            '2' { 
                $service = 'HybridAnalysis'
                break
            }
            default { 
                Write-Host "Invalid choice. Please enter 1 or 2." -ForegroundColor Red
            }
        }
    } while (-not $service)
    
    # Get API key to test
    $apiKey = Read-Host "`nEnter $service API key to test"
    if ([string]::IsNullOrWhiteSpace($apiKey)) {
        Write-Host "API key cannot be empty." -ForegroundColor Red
        return
    }
    
    Write-Host "`nTesting $service API key..." -NoNewline
    $testResult = Test-APIKeyLocally -Service $service -APIKey $apiKey
    
    if ($testResult.success) {
        Write-Host " SUCCESS!" -ForegroundColor Green
        Write-Host ""
        Write-Host "[SUCCESS] $($testResult.message)" -ForegroundColor Green
        Write-Host "[SUCCESS] Rate limits: $($testResult.tier_info)" -ForegroundColor Green
    }
    else {
        Write-Host " FAILED!" -ForegroundColor Red
        Write-Host ""
        Write-Host "[ERROR] $($testResult.message)" -ForegroundColor Red
    }
}

function Start-APIKeyManagementInterface {
    Show-APIKeyMenu
    
    # Initialize configuration
    Initialize-Config
    
    # Load config
    $config = Load-Config
    
    if ($null -eq $config) {
        Write-Host "[!] No configuration file found. Creating default configuration..." -ForegroundColor Yellow
        Initialize-Config
        $config = Load-Config
        Write-Host "[SUCCESS] Default configuration created." -ForegroundColor Green
    }
    else {
        Write-Host "[SUCCESS] Configuration loaded successfully." -ForegroundColor Green
    }
    
    Write-Host ""
    
    do {
        Show-MenuOptions
        
        $choice = Read-Host "Enter your choice (1-6)"
        
        switch ($choice) {
            '1' {
                Show-APIKeys -config $config
            }
            '2' {
                Add-APIKey -config $config
            }
            '3' {
                Update-APIKey -config $config
            }
            '4' {
                Remove-APIKey -config $config
            }
            '5' {
                Test-APIKeyInteractive -config $config
            }
            '6' {
                Write-Host "`nGoodbye!" -ForegroundColor Green
                break
            }
            default {
                Write-Host "`n[!] Invalid choice. Please enter a number between 1 and 6." -ForegroundColor Red
            }
        }
        
        if ($choice -ne '6') {
            Write-Host ""
            Write-Host "=" * 60
            Write-Host ""
            $null = Read-Host "Press Enter to continue..."
        }
    } while ($choice -ne '6')
}

# Run the interface if this script is executed directly
Start-APIKeyManagementInterface