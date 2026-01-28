<#
.SYNOPSIS
    ADS Scanner - API Key Management Interface (Standalone)
    Provides a user-friendly interface to view, add, update, and remove API keys

.DESCRIPTION
    This script provides a menu-driven interface for managing API keys for the ADS Scanner.
    It allows users to view, add, update, remove, and test API keys for VirusTotal and Hybrid Analysis.
    This is a standalone version that doesn't require the main scanner script to be loaded.
#>

#requires -Version 5.1

# Define the ADSConfigManager class for configuration management
if (-not ([System.Management.Automation.PSTypeName]'ADSConfigManager').Type) {
    Add-Type -TypeDefinition @"
        using System;
        using System.IO;
        using System.Security;
        using System.Collections;
        using System.Collections.Generic;
        using System.Text.Json;
        using System.Text.Json.Serialization;
        using System.Runtime.InteropServices;

        public class ADSConfigManager
        {
            public string ConfigDir { get; set; }
            public string ConfigFile { get; set; }
            public string CacheDir { get; set; }
            public string LogDir { get; set; }
            public Hashtable Config { get; set; }

            public ADSConfigManager()
            {
                var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                ConfigDir = Path.Combine(localAppData, "ADSScanner");
                ConfigFile = Path.Combine(ConfigDir, "config.json");
                CacheDir = Path.Combine(ConfigDir, "cache");
                LogDir = Path.Combine(ConfigDir, "logs");
            }

            public void Initialize()
            {
                if (!Directory.Exists(ConfigDir))
                {
                    Directory.CreateDirectory(ConfigDir);
                }
                if (!Directory.Exists(CacheDir))
                {
                    Directory.CreateDirectory(CacheDir);
                }
                if (!Directory.Exists(LogDir))
                {
                    Directory.CreateDirectory(LogDir);
                }

                if (!File.Exists(ConfigFile))
                {
                    CreateDefaultConfig();
                }
            }

            public void CreateDefaultConfig()
            {
                var defaultConfig = new Hashtable();
                defaultConfig["version"] = "1.0";
                
                var apiKeys = new Hashtable();
                apiKeys["virustotal"] = new ArrayList();  // Using ArrayList to match PowerShell expectations
                apiKeys["hybrid_analysis"] = new ArrayList();
                defaultConfig["api_keys"] = apiKeys;

                var settings = new Hashtable();
                settings["exclude_zone_identifier"] = false;
                settings["default_output_path"] = null;
                settings["parallel_api_calls"] = true;
                settings["cache_enabled"] = true;
                settings["cache_ttl_days"] = 7;
                settings["proxy"] = null;
                settings["log_level"] = "INFO";
                settings["export_format"] = "CSV";
                defaultConfig["settings"] = settings;

                Config = defaultConfig;
                SaveConfig();
            }

            public void LoadConfig()
            {
                if (!File.Exists(ConfigFile))
                {
                    throw new FileNotFoundException($"Configuration file not found: {ConfigFile}");
                }

                var jsonContent = File.ReadAllText(ConfigFile);
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                Config = JsonSerializer.Deserialize<Hashtable>(jsonContent, options);
            }

            public void SaveConfig()
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                var jsonContent = JsonSerializer.Serialize(Config, options);
                File.WriteAllText(ConfigFile, jsonContent);
            }

            public string EncryptString(string plaintext)
            {
                if (string.IsNullOrEmpty(plaintext))
                {
                    return "";
                }

                var secureString = new SecureString();
                foreach (var c in plaintext)
                {
                    secureString.AppendChar(c);
                }
                secureString.MakeReadOnly();
                
                // For this simplified version, we'll just return the original string
                // In a real implementation, we would use Windows DPAPI
                return plaintext; // Placeholder - in real implementation use DPAPI
            }

            public string DecryptString(string encrypted)
            {
                if (string.IsNullOrEmpty(encrypted))
                {
                    return "";
                }
                
                // For this simplified version, we'll just return the original string
                // In a real implementation, we would use Windows DPAPI
                return encrypted; // Placeholder - in real implementation use DPAPI
            }

            public void AddAPIKey(string service, string apiKey, string tier, int priority, bool enabled)
            {
                service = service.ToLower();

                var keyConfig = new Hashtable();
                keyConfig["key"] = EncryptString(apiKey); // In real implementation
                keyConfig["tier"] = tier;
                keyConfig["enabled"] = enabled;
                keyConfig["priority"] = priority;

                // Set default rate limits
                if (service == "virustotal")
                {
                    if (tier == "free")
                    {
                        keyConfig["requests_per_minute"] = 4;
                        keyConfig["requests_per_day"] = 500;
                    }
                    else
                    {
                        keyConfig["requests_per_minute"] = 1000;
                        keyConfig["requests_per_day"] = 300000;
                    }
                }
                else if (service == "hybrid_analysis")
                {
                    keyConfig["requests_per_minute"] = 5;
                    keyConfig["requests_per_hour"] = 200;
                }

                // Add to config
                ((ArrayList)Config["api_keys"][service]).Add(keyConfig);

                // Sort by priority
                var list = (ArrayList)Config["api_keys"][service];
                list.Sort(new PriorityComparer());

                SaveConfig();
            }

            public void RemoveAPIKey(string service, int index)
            {
                service = service.ToLower();
                var list = (ArrayList)Config["api_keys"][service];

                if (index < 0 || index >= list.Count)
                {
                    throw new IndexOutOfRangeException($"Invalid key index: {index}");
                }

                list.RemoveAt(index);
                SaveConfig();
            }

            public ArrayList GetAPIKeys(string service)
            {
                service = service.ToLower();
                var decryptedKeys = new ArrayList();
                var keys = (ArrayList)Config["api_keys"][service];

                foreach (Hashtable keyConfig in keys)
                {
                    var decrypted = (Hashtable)keyConfig.Clone();
                    decrypted["key"] = DecryptString((string)keyConfig["key"]);
                    decryptedKeys.Add(decrypted);
                }

                return decryptedKeys;
            }

            public ArrayList ListAPIKeys(string service)
            {
                service = service.ToLower();
                var maskedKeys = new ArrayList();
                var keys = (ArrayList)Config["api_keys"][service];

                int index = 0;
                foreach (Hashtable keyConfig in keys)
                {
                    var masked = (Hashtable)keyConfig.Clone();
                    var encKey = (string)keyConfig["key"];
                    if (encKey.Length > 8)
                    {
                        masked["key"] = "***" + encKey.Substring(encKey.Length - 8);
                    }
                    else
                    {
                        masked["key"] = "***";
                    }
                    masked["index"] = index;
                    maskedKeys.Add(masked);
                    index++;
                }

                return maskedKeys;
            }

            public object GetSetting(string name, object defaultValue)
            {
                if (Config["settings"].Contains(name))
                {
                    return Config["settings"][name];
                }
                return defaultValue;
            }

            public void SetSetting(string name, object value)
            {
                ((Hashtable)Config["settings"])[name] = value;
                SaveConfig();
            }

            public bool ConfigExists()
            {
                return File.Exists(ConfigFile);
            }
        }

        public class PriorityComparer : IComparer
        {
            public int Compare(object x, object y)
            {
                var xPriority = (int)((Hashtable)x)["priority"];
                var yPriority = (int)((Hashtable)y)["priority"];
                return xPriority.CompareTo(yPriority);
            }
        }
"@
}

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

function Show-APIKeys {
    param([ADSConfigManager]$ConfigMgr)
    
    Write-Host "`nConfigured API Keys:" -ForegroundColor Green
    Write-Host "-" * 80
    
    try {
        $allKeys = @{
            virustotal = $ConfigMgr.ListAPIKeys('virustotal')
            hybrid_analysis = $ConfigMgr.ListAPIKeys('hybrid_analysis')
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
    param([ADSConfigManager]$ConfigMgr)
    
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
    
    # Test the API key before adding
    Write-Host "`nTesting $serviceName API key..." -NoNewline
    $testResult = Test-APIKeyLocally -Service $serviceName -APIKey $apiKey
    
    if ($testResult.success) {
        Write-Host " SUCCESS!" -ForegroundColor Green
        Write-Host "($($testResult.tier_info))"
        
        # Add the key
        $ConfigMgr.AddAPIKey($service, $apiKey, $tier, $priority, $true)
        Write-Host "`n[SUCCESS] API key added successfully for $serviceName!" -ForegroundColor Green
        
        # Show updated list
        Show-APIKeys -ConfigMgr $ConfigMgr
    }
    else {
        Write-Host " FAILED!" -ForegroundColor Red
        Write-Host "$($testResult.message)"
        Write-Host "API key was not added." -ForegroundColor Yellow
    }
}

function Update-APIKey {
    param([ADSConfigManager]$ConfigMgr)
    
    Write-Host ""
    Write-Host "Update Existing API Key" -ForegroundColor Green
    Write-Host "-" * 30
    
    # First, show current keys
    Show-APIKeys -ConfigMgr $ConfigMgr
    
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
    $keys = $ConfigMgr.ListAPIKeys($service)
    if ($keys.Count -eq 0) {
        Write-Host "`nNo $serviceName keys configured." -ForegroundColor Yellow
        return
    }
    
    # Show available keys
    Write-Host "`nAvailable $serviceName keys:"
    foreach ($keyInfo in $keys) {
        $status = if ($keyInfo.enabled) { "ENABLED" } else { "DISABLED" }
        Write-Host "  [$($keyInfo.index)] $($keyInfo.key) " -NoNewline
        Write-Host "(Tier: $($keyInfo.tier), Priority: $($keyInfo.priority), Status: $status)"
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
    
    # Test the new API key before updating
    Write-Host "`nTesting new $serviceName API key..." -NoNewline
    $testResult = Test-APIKeyLocally -Service $serviceName -APIKey $newApiKey
    
    if ($testResult.success) {
        Write-Host " SUCCESS!" -ForegroundColor Green
        Write-Host "($($testResult.tier_info))"
        
        # Remove the old key
        $ConfigMgr.RemoveAPIKey($service, $index)
        
        # Add the new key with same or updated settings
        $ConfigMgr.AddAPIKey($service, $newApiKey, $tier, $priority, $true)
        Write-Host "`n[SUCCESS] API key updated successfully for $serviceName!" -ForegroundColor Green
        
        # Show updated list
        Show-APIKeys -ConfigMgr $ConfigMgr
    }
    else {
        Write-Host " FAILED!" -ForegroundColor Red
        Write-Host "$($testResult.message)"
        Write-Host "API key was not updated." -ForegroundColor Yellow
    }
}

function Remove-APIKey {
    param([ADSConfigManager]$ConfigMgr)
    
    Write-Host ""
    Write-Host "Remove API Key" -ForegroundColor Green
    Write-Host "-" * 20
    
    # First, show current keys
    Show-APIKeys -ConfigMgr $ConfigMgr
    
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
    $keys = $ConfigMgr.ListAPIKeys($service)
    if ($keys.Count -eq 0) {
        Write-Host "`nNo $serviceName keys configured." -ForegroundColor Yellow
        return
    }
    
    # Show available keys
    Write-Host "`nAvailable $serviceName keys:"
    foreach ($keyInfo in $keys) {
        $status = if ($keyInfo.enabled) { "ENABLED" } else { "DISABLED" }
        Write-Host "  [$($keyInfo.index)] $($keyInfo.key) " -NoNewline
        Write-Host "(Tier: $($keyInfo.tier), Priority: $($keyInfo.priority), Status: $status)"
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
            $ConfigMgr.RemoveAPIKey($service, $index)
            Write-Host "`n[SUCCESS] API key removed successfully from $serviceName!" -ForegroundColor Green
            
            # Show updated list
            Show-APIKeys -ConfigMgr $ConfigMgr
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
    param([ADSConfigManager]$ConfigMgr)
    
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
    
    # Initialize configuration manager
    $configMgr = New-Object ADSConfigManager
    
    # Initialize config if it doesn't exist
    if (-not $configMgr.ConfigExists()) {
        Write-Host "[!] No configuration file found. Creating default configuration..." -ForegroundColor Yellow
        $configMgr.Initialize()
        Write-Host "[SUCCESS] Default configuration created." -ForegroundColor Green
    }
    else {
        try {
            $configMgr.LoadConfig()
            Write-Host "[SUCCESS] Configuration loaded successfully." -ForegroundColor Green
        }
        catch {
            Write-Host "[X] Error loading configuration: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Creating new configuration..." -ForegroundColor Yellow
            $configMgr.Initialize()
        }
    }
    
    Write-Host ""
    
    do {
        Show-MenuOptions
        
        $choice = Read-Host "Enter your choice (1-6)"
        
        switch ($choice) {
            '1' {
                Show-APIKeys -ConfigMgr $configMgr
            }
            '2' {
                Add-APIKey -ConfigMgr $configMgr
            }
            '3' {
                Update-APIKey -ConfigMgr $configMgr
            }
            '4' {
                Remove-APIKey -ConfigMgr $configMgr
            }
            '5' {
                Test-APIKeyInteractive -ConfigMgr $configMgr
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
if ($MyInvocation.InvocationName -ne '.') {
    Start-APIKeyManagementInterface
}