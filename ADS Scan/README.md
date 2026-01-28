# ADS Scanner - Advanced NTFS Alternate Data Stream Security Auditing Tool

A comprehensive security auditing tool for detecting, analyzing, and quarantining hidden threats in Windows NTFS Alternate Data Streams (ADS). Integrates with multiple threat intelligence services (VirusTotal, Hybrid Analysis, AlienVault OTX, MetaDefender, Any.Run) to identify malicious content hidden in file system metadata.

## 📖 What Are Alternate Data Streams?

Alternate Data Streams (ADS) are a feature of the Windows NTFS file system that allows files to contain multiple streams of data. While primarily used for legitimate purposes (like storing file metadata), ADS can be abused by attackers to:

- **Hide malware** alongside legitimate files without changing file size
- **Bypass antivirus** detection by storing malicious payloads in hidden streams
- **Maintain persistence** by hiding scripts and executables
- **Exfiltrate data** by concealing sensitive information

This tool helps security professionals, system administrators, and forensic analysts discover and analyze these hidden streams.

## 🚀 Key Features

### Threat Intelligence Integration
- **VirusTotal Integration** - Hash lookups with malware detection statistics
- **Hybrid Analysis Integration** - Behavioral analysis and threat scoring
- **AlienVault OTX Integration** - Threat intelligence and reputation data
- **MetaDefender Integration** - File reputation and threat analysis
- **Any.Run Integration** - Dynamic malware analysis
- **Combined Risk Assessment** - Intelligent risk scoring (HIGH/MEDIUM/LOW/UNKNOWN)
- **Parallel API Calls** - Query multiple services simultaneously for faster scans

### Advanced API Key Management
- **Multiple API Keys Per Service** - Add unlimited keys for each service
- **Automatic Key Rotation** - Switch keys automatically when rate limits hit
- **DPAPI Encryption** - API keys encrypted using Windows Data Protection API
- **Configuration File** - Persistent storage at `%LOCALAPPDATA%\ADSScanner\config.json`
- **Interactive Setup** - First-run wizard for easy configuration

### Enhanced Performance & Reliability
- **Results Caching** - SQLite-based cache reduces redundant API calls
- **Resume Capability** - Continue interrupted scans from previous reports
- **Incremental Saving** - Results saved progressively to prevent data loss
- **Proxy Support** - HTTP/HTTPS proxy configuration
- **Logging System** - Detailed logs at `%LOCALAPPDATA%\ADSScanner\logs\`

### Stream Extraction & Quarantine
- **Automatic Extraction** - Extract suspicious ADS to quarantine directory for analysis
- **Selective Filtering** - Extract all, suspicious, high-risk, or malicious streams only
- **Metadata Preservation** - Each extracted stream includes detailed metadata sidecar file
- **Extraction Manifest** - JSON manifest tracks all extracted streams with hash and risk level
- **Safe Analysis** - Analyze extracted streams in isolated sandbox environment

### Multiple Export Formats
- **CSV** - Traditional spreadsheet format (default)
- **JSON** - Structured data with scan metadata
- **HTML** - Interactive web report with filtering and charts
- **STIX 2.1** - Threat intelligence sharing format for SIEM integration

### Rate Limiting
- **VirusTotal** - Free: 4 req/min, 500/day | Paid: 1000 req/min, 300k/day
- **Hybrid Analysis** - Free: 5 req/min, 200/hour
- **AlienVault OTX** - 1000 req/day
- **MetaDefender** - 10 req/min
- **Any.Run** - 10 req/min
- **Automatic Waiting** - Smart delays to stay within limits
- **Multi-Key Aggregation** - Combine quotas across multiple keys

## 📋 Requirements

### Python Script (Recommended)
- Python 3.6 or higher
- Windows OS with NTFS filesystem
- No external dependencies (uses only standard library)
- Optional: API keys for threat intelligence services

### PowerShell Script
- Windows PowerShell 5.1+ or PowerShell Core 7+
- Administrator privileges recommended for full system scans
- NTFS filesystem
- Optional: API keys for threat intelligence services

## 🔑 Getting API Keys

### VirusTotal (Free/Paid)
1. Go to https://www.virustotal.com/
2. Sign up for a free account
3. Navigate to your profile → API Key section
4. Copy your API key
5. Free tier: 4 requests/minute, 500/day

### Hybrid Analysis (Free/Paid)
1. Go to https://www.hybrid-analysis.com/
2. Create a free account
3. Go to Profile → API Key
4. Generate and copy your API key
5. Free tier: 5 requests/minute, 200/hour

### AlienVault OTX (Free)
1. Go to https://otx.alienvault.com/
2. Create a free account
3. Go to Settings → API Key
4. Copy your API key

### MetaDefender (Free/Paid)
1. Go to https://metadefender.opswat.com/
2. Create an account
3. Access your API key from the dashboard

### Any.Run (Free/Paid)
1. Go to https://any.run/
2. Create an account
3. Access your API key from the account settings

**Treat API keys like passwords - never commit them to version control!**

## 💻 Quick Start (Python v2.1)

### First-Run Setup (Interactive)

```bash
python scan_ads.py --setup
```

This launches an interactive wizard that:
- Tests your API keys before saving
- Configures all threat intelligence services
- Encrypts keys using Windows DPAPI
- Sets default preferences (caching, Zone.Identifier exclusion, etc.)
- Saves configuration to `%LOCALAPPDATA%\ADSScanner\config.json`

### Configuration Management (CLI)

**Initialize configuration:**
```bash
python scan_ads.py --config init
```

**Add VirusTotal API key:**
```bash
python scan_ads.py --config add --service virustotal --key "YOUR_VT_KEY" --tier free
```

**Add Hybrid Analysis API key:**
```bash
python scan_ads.py --config add --service hybrid-analysis --key "YOUR_HA_KEY"
```

**Add AlienVault OTX API key:**
```bash
python scan_ads.py --config add --service alienvault-otx --key "YOUR_OTX_KEY"
```

**Add MetaDefender API key:**
```bash
python scan_ads.py --config add --service metadefender --key "YOUR_MD_KEY"
```

**Add Any.Run API key:**
```bash
python scan_ads.py --config add --service any-run --key "YOUR_AR_KEY"
```

**List configured keys (keys are masked):**
```bash
python scan_ads.py --config list
```

**Test an API key:**
```bash
python scan_ads.py --config test --service virustotal --key "YOUR_KEY"
```

**Remove a key:**
```bash
python scan_ads.py --config remove --service virustotal --index 0
```

### Scanning with Configuration File

**Basic scan (uses all configured services):**
```bash
python scan_ads.py C:\Users --use-config
```

**Export as HTML:**
```bash
python scan_ads.py C:\Users --use-config --export-format html
```

**Export as JSON:**
```bash
python scan_ads.py C:\Users --use-config --export-format json
```

**Export as STIX 2.1 (for SIEM integration):**
```bash
python scan_ads.py C:\Users --use-config --export-format stix
```

**Skip specific services:**
```bash
python scan_ads.py C:\Users --use-config --skip-virustotal --skip-hybrid-analysis
```

**Use proxy:**
```bash
python scan_ads.py C:\Users --use-config --proxy http://proxy.company.com:8080
```

**Disable caching:**
```bash
python scan_ads.py C:\Users --use-config --no-cache
```

**Resume interrupted scan:**
```bash
python scan_ads.py C:\Users --use-config --resume ADS_Report_20260128_120000.csv
```

**Extract streams to quarantine directory:**
```bash
# Extract all ADS to quarantine directory
python scan_ads.py C:\Users --use-config --extract quarantine/

# Extract only high-risk streams
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter high-risk

# Extract only malicious streams (VT or HA confirmed malware)
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter malicious

# Extract suspicious or worse (medium/high risk)
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter suspicious
```

### Legacy Mode (Backward Compatible)

**Single VirusTotal key (no config file):**
```bash
python scan_ads.py C:\Users --api-key "YOUR_VT_KEY"
```

**Offline scan (no API keys):**
```bash
python scan_ads.py C:\Users --skip-virustotal
```

## 💻 PowerShell Usage

### Basic Scanning

**Scan with all services:**
```powershell
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig
```

**Exclude Zone.Identifier streams:**
```powershell
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Temp" -ExcludeZoneIdentifier -UseConfig
```

**Custom output location:**
```powershell
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Projects" -OutputFile "C:\Reports\ads_scan.csv" -UseConfig
```

**Resume from previous scan:**
```powershell
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -ResumeFile "ADS_Report_VT_20260128.csv" -UseConfig
```

**Offline scan (no API):**
```powershell
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Temp" -SkipVirusTotal
```

## 📊 Understanding the Reports

### CSV Report Columns

#### File Information
- **FilePath** - Full path to the file
- **FileName** - File name only
- **FileSize** - File size in bytes
- **FileExtension** - File extension
- **FileCreated/Modified/Accessed** - File timestamps

#### Stream Information
- **StreamName** - Name of the alternate data stream
- **StreamSize** - Stream size in bytes
- **StreamType** - Text, Binary, or Empty
- **StreamSHA256** - SHA256 hash of stream content
- **StreamPreview** - First 200 chars (text) or 50 bytes hex (binary)

#### VirusTotal Results
- **VT_Found** - Whether hash exists in VT database (True/False)
- **VT_DetectionRatio** - Detections (e.g., "3/72" = 3 engines detected as malicious)
- **VT_Malicious** - Number of engines flagging as malicious
- **VT_Suspicious** - Number of engines flagging as suspicious
- **VT_Undetected** - Number of engines with no detection
- **VT_Harmless** - Number of engines flagging as harmless
- **VT_DetectionEngines** - List of detecting engines and signatures
- **VT_ScanDate** - Date of last VT analysis
- **VT_Link** - Direct link to VT report

#### Hybrid Analysis Results
- **HA_Found** - Whether hash exists in HA database (True/False)
- **HA_ThreatScore** - Threat score 0-100 (70+ = malicious, 40-69 = suspicious)
- **HA_Verdict** - malicious, suspicious, or no-verdict
- **HA_AVDetect** - Percentage of AV engines detecting
- **HA_VXFamily** - Malware family name (if identified)
- **HA_JobID** - Hybrid Analysis job ID
- **HA_ReportURL** - Direct link to HA report
- **HA_ScanDate** - Date of HA analysis

#### AlienVault OTX Results
- **OTX_Found** - Whether hash exists in OTX database (True/False)
- **OTX_PulseCount** - Number of pulses associated with the hash
- **OTX_MalwareFamilies** - List of malware families identified
- **OTX_Reputation** - Reputation score
- **OTX_Link** - Direct link to OTX report

#### MetaDefender Results
- **MD_Found** - Whether hash exists in MetaDefender database (True/False)
- **MD_DetectionRatio** - Detection ratio (e.g., "2/16")
- **MD_ScanAllResult** - Overall scan result
- **MD_Link** - Direct link to MetaDefender report

#### Any.Run Results
- **AR_Found** - Whether hash exists in Any.Run database (True/False)
- **AR_Malicious** - Whether file is flagged as malicious
- **AR_Verdict** - Verdict from Any.Run
- **AR_Score** - Threat score (0-100)
- **AR_Link** - Direct link to Any.Run report

#### Combined Analysis
- **Combined_Risk** - Overall risk: HIGH, MEDIUM, LOW, or UNKNOWN
  - **HIGH**: VT malicious ≥ 3 OR HA score ≥ 70 OR AR malicious
  - **MEDIUM**: VT malicious > 0 OR HA score ≥ 40 OR VT suspicious ≥ 5 OR AR score > 50
  - **LOW**: VT malicious = 0 AND HA score < 20 AND AR score < 30
  - **UNKNOWN**: Not found in any database

- **FlagForSubmission** - YES if not in any database, NO otherwise

#### Metadata
- **CachedResult** - YES if from cache, NO if fresh API call
- **APIKeysUsed** - Which services were queried (VT, HA, OTX, MD, AR, or combinations)
- **ScanDate** - Timestamp of this scan

### JSON Report Structure

```json
{
  "scan_metadata": {
    "scan_date": "2026-01-28T10:30:00",
    "scan_path": "C:\\Users",
    "total_streams": 42,
    "statistics": {
      "high_risk": 2,
      "medium_risk": 5,
      "low_risk": 30,
      "unknown_risk": 5,
      "malicious_vt": 2,
      "malicious_ha": 1,
      "malicious_otx": 0,
      "malicious_md": 0,
      "malicious_ar": 1
    },
    "api_usage": {
      "virustotal": {
        "total_keys": 2,
        "total_requests": 35,
        "remaining_quota": 965
      },
      "hybrid_analysis": {
        "total_keys": 1,
        "total_requests": 30,
        "remaining_quota": 170
      }
    },
    "cache_stats": {
      "cache_hits": 15,
      "cache_misses": 25,
      "hit_rate": "37.5%"
    }
  },
  "results": [
    { /* individual stream results */ }
  ]
}
```

### HTML Report Features

- **Interactive Filtering** - Search by filename or stream name
- **Risk Level Filter** - Show only HIGH, MEDIUM, LOW, or UNKNOWN
- **Color-Coded Badges** - Visual risk indicators
- **Clickable Links** - Direct access to VT, HA, OTX, MD, and AR reports
- **Summary Statistics** - Risk distribution at a glance
- **Responsive Design** - Works on desktop and mobile browsers

### STIX 2.1 Format

Exports malicious findings as STIX 2.1 indicators for integration with:
- SIEM platforms (Splunk, QRadar, Sentinel)
- Threat intelligence platforms (MISP, OpenCTI)
- Security orchestration tools

## 🔒 Security Considerations

### API Key Security
- **DPAPI Encryption** - Keys encrypted using Windows Data Protection API
- **User-Specific** - Encrypted keys only work for the Windows user who encrypted them
- **Config File Permissions** - Stored in user's local app data with restrictive ACLs
- **No Plaintext Storage** - Keys never stored in plaintext

### Script Safety
- **Read-Only Operations** - Scripts only READ alternate data streams
- **No Execution** - Discovered streams are never executed
- **No Modification** - Scripts cannot modify or delete streams
- **Hash-Based Lookups** - Only SHA256 hashes are sent to APIs (not file content)

### Best Practices
1. **Never commit config files** to version control
2. **Use separate API keys** for different environments (dev/prod)
3. **Monitor API usage** to detect unauthorized key use
4. **Regularly rotate keys** for production systems
5. **Review logs** for suspicious activity

## 📈 Performance Tips

### Optimize Scan Speed
- **Use multiple API keys** - Aggregate quotas for faster scans
- **Enable caching** - Avoid re-querying known hashes
- **Parallel API calls** - Query multiple services simultaneously (enabled by default)
- **Exclude Zone.Identifier** - Reduce noise from download markers
- **Resume capability** - Continue large scans across multiple sessions

### Managing Large Scans
- **Scan in segments** - Break large drives into directories
- **Use resume files** - Interrupt and continue without losing progress
- **Monitor rate limits** - Track daily/hourly quotas with `--log-level DEBUG`
- **Schedule scans** - Run during off-hours to avoid rate limit exhaustion

### Cache Tuning
- **Default TTL**: 7 days (configurable)
- **Storage**: SQLite database at `%LOCALAPPDATA%\ADSScanner\cache\results.db`
- **Pruning**: Expired entries auto-removed on startup
- **Manual clear**: Delete cache database or use `--no-cache`

## 🛠️ API Key Manager

The tool includes a user-friendly API key management interface:

```bash
python api_key_manager.py
```

Features:
- View configured API keys
- Add new API keys
- Update existing API keys
- Remove API keys
- Test existing or new API keys
- Support for all integrated services

## 🛠️ Troubleshooting

### "No configuration file found"
**Solution:** Run `python scan_ads.py --setup` to create initial configuration.

### "API key test failed"
**Causes:**
- Invalid or expired API key
- Network connectivity issues
- Proxy blocking API requests

**Solution:**
- Verify key at the respective service website
- Test network: `curl https://www.virustotal.com/api/v3/files/test`
- Configure proxy: `--proxy http://proxy:8080`

### "Failed to decrypt data with DPAPI"
**Cause:** Config file created by different Windows user

**Solution:**
- Run `python scan_ads.py --setup` with current user
- Or delete `%LOCALAPPDATA%\ADSScanner\config.json` and reconfigure

### "Rate limit exceeded"
**Solution:**
- Wait for rate limit window to reset
- Add additional API keys for the service
- Use `--no-cache` temporarily to verify behavior

### High memory usage
**Cause:** Large number of results held in memory

**Solution:**
- Scan smaller directory trees
- Results are saved incrementally (every 10 streams)
- Memory freed after CSV export

## 📁 File Structure

```
ADS-Scanner/
├── scan_ads.py              # Main Python scanner (v2.1)
├── Scan-AlternateDataStreams-VT.ps1  # PowerShell scanner
├── api_key_manager.py          # API key management interface
├── config_manager.py           # Configuration and DPAPI encryption
├── api_clients.py              # Threat intelligence API clients
├── key_rotator.py              # Multi-key rotation manager
├── cache_manager.py            # SQLite results cache
├── export_formats.py           # JSON, HTML, STIX exporters
├── test_ads_scanner.py         # Unit tests
├── README.md                   # This file
└── %LOCALAPPDATA%\ADSScanner\  # User configuration directory
    ├── config.json             # Encrypted API keys and settings
    ├── cache\
    │   └── results.db          # SQLite cache database
    └── logs\
        └── scan_*.log          # Scan logs
```

## 🧪 Testing

### Run Unit Tests

```bash
python test_ads_scanner.py
```

Tests cover:
- DPAPI encryption/decryption
- Configuration management
- API key rotation logic
- Cache operations
- Risk calculation algorithms

### Create Test ADS

```powershell
# Create test file with alternate data stream
echo "main file content" > test.txt
echo "hidden stream data" > test.txt:hidden
echo "another stream" > test.txt:secret

# Verify streams
Get-Item test.txt -Stream *
```

### Test with Known Hashes

**EICAR Test File** (harmless malware test):
```
SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```
Should trigger HIGH risk detections in all services.

## 📝 Use Cases

### Security Auditing
- **Enterprise Security**: Scan workstations and servers for hidden malware
- **Incident Response**: Investigate compromised systems for persistence mechanisms
- **Compliance**: Demonstrate thorough file system security scanning

### Threat Hunting
- **APT Detection**: Identify sophisticated malware using ADS for persistence
- **Data Exfiltration**: Detect hidden data staged in alternate streams
- **Forensic Analysis**: Collect comprehensive ADS inventory with threat intel

### Development & Testing
- **Malware Analysis**: Study how malware uses ADS
- **Security Research**: Analyze prevalence of ADS in the wild
- **Product Testing**: Verify security software detects ADS-based threats

## 🤝 Contributing

This is a security auditing tool. When contributing:
- Maintain read-only file operations (never execute or modify streams)
- Preserve feature parity between Python and PowerShell versions
- Add unit tests for new functionality
- Update documentation (README, API docs)
- Never commit API keys or configuration files

## 📄 License

This tool is for **authorized security auditing only**. Do not use on systems without proper authorization.

## 🔗 Resources

- **VirusTotal API Docs**: https://developers.virustotal.com/reference/overview
- **Hybrid Analysis API Docs**: https://www.hybrid-analysis.com/docs/api/v2
- **AlienVault OTX API Docs**: https://otx.alienvault.com/api
- **MetaDefender API Docs**: https://metadefender.opswat.com/
- **Any.Run API Docs**: https://any.run/
- **NTFS ADS Microsoft Docs**: https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams
- **STIX 2.1 Specification**: https://docs.oasis-open.org/cti/stix/v2.1/

## 📞 Support

For issues, questions, or feature requests:
1. Check the Troubleshooting section above
2. Review logs at `%LOCALAPPDATA%\ADSScanner\logs\`
3. Run with `--log-level DEBUG` for verbose output
4. Open an issue with:
   - Scanner version (Python v2.1 or PowerShell)
   - Error messages from logs
   - Steps to reproduce
   - Operating system version

---

**Version**: 2.1.0
**Last Updated**: 2026-01-28
**Python**: 3.6+ | **PowerShell**: 5.1+