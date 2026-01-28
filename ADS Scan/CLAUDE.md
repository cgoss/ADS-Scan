# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains security auditing tools for scanning Windows NTFS Alternate Data Streams (ADS) with **multi-service threat intelligence** integration (VirusTotal + Hybrid Analysis). The project provides parallel implementations in both PowerShell and Python for maximum compatibility across different Windows environments.

**Version**: 2.0.0
**Status**: Production Ready
**Purpose**: Detect hidden malicious content, security threats, and unknown files embedded in NTFS alternate data streams - a common technique used by attackers to hide malware.

## Architecture v2.0

### Dual Implementation Strategy

The codebase maintains **98% feature parity** between two independent implementations:

1. **Python Script** (`scan_ads.py`) - 890 lines
   - Modular architecture with 6 separate modules
   - Uses Windows API via `ctypes` (`FindFirstStreamW`, `FindNextStreamW`)
   - SQLite-based caching
   - ThreadPoolExecutor for parallel API calls
   - No external dependencies (stdlib only)

2. **PowerShell Script** (`Scan-AlternateDataStreams-VT.ps1`) - 1,550 lines
   - Monolithic script with embedded classes
   - Uses native Windows PowerShell cmdlets (`Get-Item -Stream`)
   - JSON file-based caching
   - Sequential API calls (simpler implementation)
   - PowerShell 5.1+ compatible

**Critical**: When adding features or fixing bugs, changes MUST be synchronized across both implementations to maintain feature parity.

### Core Architecture (v2.0)

#### Python Modules

```
scan_ads.py (890 lines)         # Main scanner with CLI
├── config_manager.py (561 lines)  # Configuration + DPAPI encryption
├── api_clients.py (327 lines)     # VT and HA API clients
├── key_rotator.py (197 lines)     # Multi-key rotation
├── cache_manager.py (224 lines)   # SQLite results cache
├── export_formats.py (477 lines)  # JSON, HTML, STIX exporters
└── test_ads_scanner.py (342 lines) # Unit tests
```

#### PowerShell Modules

```
Scan-AlternateDataStreams-VT.ps1 (1,550 lines)  # Main scanner
├── [Embedded Classes]
│   ├── ADSConfigManager          # Configuration + DPAPI
│   ├── VirusTotalAPIClient       # VT API client
│   ├── HybridAnalysisAPIClient   # HA API client
│   └── APIKeyRotator             # Multi-key rotation
│
├── [Dot-sourced Modules]
│   ├── ADSCache.ps1 (120 lines)          # JSON-based cache
│   └── ADSExportFormats.ps1 (375 lines)  # Export handlers
```

### Data Flow (v2.0)

```
File System → Stream Enumeration → Hash Calculation
                                         ↓
                                    Cache Check ─→ Cache Hit ─→ Return Cached
                                         ↓ Miss
                                    API Key Rotation
                                         ↓
                              ┌──────────┴──────────┐
                              ↓                     ↓
                        VirusTotal           Hybrid Analysis
                        (Parallel)           (Parallel)
                              ↓                     ↓
                              └──────────┬──────────┘
                                         ↓
                              Combined Risk Assessment
                                         ↓
                                   Cache Store
                                         ↓
                              CSV/JSON/HTML/STIX Export
```

## Key Components (v2.0)

### 1. Configuration Management

**Location**:
- Python: `config_manager.py` (ConfigManager, DPAPIManager classes)
- PowerShell: `Scan-AlternateDataStreams-VT.ps1` (ADSConfigManager class)

**Configuration File**: `%LOCALAPPDATA%\ADSScanner\config.json`

**Structure**:
```json
{
  "version": "1.0",
  "api_keys": {
    "virustotal": [
      {
        "key": "DPAPI_ENCRYPTED_STRING",
        "tier": "free",
        "requests_per_minute": 4,
        "requests_per_day": 500,
        "enabled": true,
        "priority": 1
      }
    ],
    "hybrid_analysis": [
      {
        "key": "DPAPI_ENCRYPTED_STRING",
        "tier": "free",
        "requests_per_minute": 5,
        "requests_per_hour": 200,
        "enabled": true,
        "priority": 1
      }
    ]
  },
  "settings": {
    "exclude_zone_identifier": false,
    "cache_enabled": true,
    "cache_ttl_days": 7,
    "proxy": null,
    "log_level": "INFO",
    "export_format": "csv"
  }
}
```

**Encryption**:
- **Python**: Uses Windows CryptProtectData/CryptUnprotectData via ctypes
- **PowerShell**: Uses ConvertTo-SecureString/ConvertFrom-SecureString
- **Security**: User-specific encryption (keys only work for encrypting user)

### 2. API Clients

#### VirusTotal API v3
**Location**:
- Python: `api_clients.py` (VirusTotalAPI class)
- PowerShell: Embedded (VirusTotalAPIClient class)

**Endpoint**: `GET https://www.virustotal.com/api/v3/files/{hash}`
**Rate Limits**:
- Free: 4 req/min, 500 req/day
- Paid: 1000 req/min, 300k req/day

**Response Mapping**:
- `last_analysis_stats.malicious` → VT_Malicious
- `last_analysis_stats.suspicious` → VT_Suspicious
- Detection ratio format: "3/72"
- Link: `https://www.virustotal.com/gui/file/{hash}`

#### Hybrid Analysis API v2
**Location**:
- Python: `api_clients.py` (HybridAnalysisAPI class)
- PowerShell: Embedded (HybridAnalysisAPIClient class)

**Endpoint**: `GET https://www.hybrid-analysis.com/api/v2/search/hash?hash={hash}`
**Headers**: `api-key`, `User-Agent: Falcon Sandbox`
**Rate Limits**: 5 req/min, 200 req/hour

**Response Mapping**:
- `threat_score` (0-100) → HA_ThreatScore
- `verdict` (malicious/suspicious/no-verdict) → HA_Verdict
- `av_detect` → HA_AVDetect
- `vx_family` → HA_VXFamily
- Report URL: `https://www.hybrid-analysis.com/sample/{job_id}`

### 3. API Key Rotation

**Location**:
- Python: `key_rotator.py` (APIKeyRotator class)
- PowerShell: Embedded (APIKeyRotator class)

**Features**:
- Unlimited keys per service
- Priority-based selection (1 = highest)
- Automatic rotation when rate limited
- Per-key daily/hourly counters
- Statistics tracking

**Algorithm**:
1. Sort keys by priority
2. Try current key
3. If rate limited, mark until reset time
4. Rotate to next available key
5. If all keys limited, return None

### 4. Results Caching

**Python**: SQLite database at `%LOCALAPPDATA%\ADSScanner\cache\results.db`

```sql
CREATE TABLE api_results (
    sha256 TEXT PRIMARY KEY,
    vt_result TEXT,
    ha_result TEXT,
    cached_at TEXT,
    expires_at TEXT
);
```

**PowerShell**: JSON file at `%LOCALAPPDATA%\ADSScanner\cache\results_cache.json`

```json
{
  "hash123": {
    "vt_result": { /* VT response */ },
    "ha_result": { /* HA response */ },
    "cached_at": "2026-01-28T10:30:00",
    "expires_at": "2026-02-04T10:30:00"
  }
}
```

**TTL**: Default 7 days (configurable)
**Pruning**: Expired entries auto-removed on startup

### 5. Combined Risk Assessment

**Location**:
- Python: `export_formats.py:425-454` (calculate_combined_risk function)
- PowerShell: `Scan-AlternateDataStreams-VT.ps1:780-811` (Calculate-CombinedRisk function)

**Algorithm**:
```
HIGH:    VT malicious >= 3 OR HA threat_score >= 70
MEDIUM:  VT malicious > 0 OR HA threat_score >= 40 OR VT suspicious >= 5
LOW:     VT malicious == 0 AND HA threat_score < 20
UNKNOWN: Not found in any database
```

**Output**: Combined_Risk column in CSV with values: HIGH, MEDIUM, LOW, UNKNOWN

### 6. Export Formats

**CSV** (default):
- 33 columns including all VT, HA, and metadata fields
- Backward compatible with v1.0 resume files

**JSON**:
- Structured with scan_metadata and results array
- Includes statistics (risk distribution, API usage, cache performance)

**HTML**:
- Interactive table with search and filtering
- Color-coded risk badges
- Links to VT and HA reports
- Risk distribution cards

**STIX 2.1**:
- Indicators for malicious hashes
- Observed-data objects with file metadata
- Compatible with MISP, OpenCTI, Splunk, etc.

## Commands

### Interactive Setup (First Run)

**Python**:
```bash
python scan_ads.py --setup
```

**PowerShell**:
```powershell
.\Scan-AlternateDataStreams-VT.ps1 -InteractiveSetup
```

### Configuration Management

**Python**:
```bash
# Initialize config
python scan_ads.py --config init

# Add API keys
python scan_ads.py --config add --service virustotal --key "YOUR_KEY" --tier free
python scan_ads.py --config add --service hybrid-analysis --key "YOUR_KEY"

# List keys (masked)
python scan_ads.py --config list

# Test a key
python scan_ads.py --config test --service virustotal --key "YOUR_KEY"

# Remove a key
python scan_ads.py --config remove --service virustotal --index 0
```

**PowerShell**:
```powershell
# Initialize config
.\Scan-AlternateDataStreams-VT.ps1 -ConfigAction Init

# Add API keys
.\Scan-AlternateDataStreams-VT.ps1 -ConfigAction Add -Service VirusTotal -Key "YOUR_KEY" -Tier Free
.\Scan-AlternateDataStreams-VT.ps1 -ConfigAction Add -Service HybridAnalysis -Key "YOUR_KEY"

# List keys (masked)
.\Scan-AlternateDataStreams-VT.ps1 -ConfigAction List

# Test a key
.\Scan-AlternateDataStreams-VT.ps1 -ConfigAction Test -Service VirusTotal -Key "YOUR_KEY"

# Remove a key
.\Scan-AlternateDataStreams-VT.ps1 -ConfigAction Remove -Service VirusTotal -Index 0
```

### Scanning

**Python**:
```bash
# Basic scan with config file
python scan_ads.py C:\Users --use-config

# Export as HTML
python scan_ads.py C:\Users --use-config --export-format html

# Export as JSON
python scan_ads.py C:\Users --use-config --export-format json

# Export as STIX for SIEM
python scan_ads.py C:\Users --use-config --export-format stix

# Skip HA (VT only)
python scan_ads.py C:\Users --use-config --skip-hybrid-analysis

# Disable caching
python scan_ads.py C:\Users --use-config --no-cache

# Use proxy
python scan_ads.py C:\Users --use-config --proxy http://proxy:8080

# Resume interrupted scan
python scan_ads.py C:\Users --use-config --resume ADS_Report_20260128.csv
```

**PowerShell**:
```powershell
# Basic scan with config file
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig

# Export as HTML
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig -ExportFormat HTML

# Export as JSON
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig -ExportFormat JSON

# Export as STIX for SIEM
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig -ExportFormat STIX

# Skip HA (VT only)
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig -SkipHybridAnalysis

# Disable caching
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig -NoCache

# Use proxy
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig -Proxy "http://proxy:8080"

# Resume interrupted scan
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -UseConfig -ResumeFile "ADS_Report_20260128.csv"
```

### Legacy Mode (Backward Compatible with v1.0)

**Python**:
```bash
# Single VT key (no config file)
python scan_ads.py C:\Users --api-key YOUR_VT_KEY

# Offline scan (no APIs)
python scan_ads.py C:\Users --skip-virustotal
```

**PowerShell**:
```powershell
# Single VT key (no config file)
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -VirusTotalAPIKey "YOUR_VT_KEY"

# Offline scan (no APIs)
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -SkipVirusTotal
```

## Key Implementation Details (v2.0)

### Stream Reading

**Python** reads streams by opening with `:streamname` syntax:
```python
stream_path = f"{file_path}:{stream_name}"
with open(stream_path, 'rb') as f:
    data = f.read()
```

**PowerShell** uses native cmdlets:
```powershell
Get-Content -Path "$($file.FullName):$($stream.Stream)" -Encoding Byte -Raw
```

### Content Type Detection

Determines if stream is Text or Binary by scanning first 100 bytes:
- Binary if contains null bytes or control characters (excluding tab/newline/CR)
- Text preview: First 200 characters decoded as UTF-8/ASCII
- Binary preview: First 50 bytes as hex string

### CSV Output Format (v2.0)

**Columns** (33 total):
- **File metadata**: FilePath, FileName, FileSize, FileExtension, FileCreated, FileModified, FileAccessed
- **Stream data**: StreamName, StreamSize, StreamType, StreamSHA256, StreamPreview
- **VT results**: VT_Found, VT_DetectionRatio, VT_Malicious, VT_Suspicious, VT_Undetected, VT_Harmless, VT_DetectionEngines, VT_ScanDate, VT_Link
- **HA results** (NEW): HA_Found, HA_ThreatScore, HA_Verdict, HA_AVDetect, HA_VXFamily, HA_JobID, HA_ReportURL, HA_ScanDate
- **Combined analysis** (NEW): Combined_Risk, FlagForSubmission
- **Metadata** (NEW): CachedResult, APIKeysUsed, ScanDate

### Resume Logic

Both implementations load SHA256 hashes from previous CSV reports and skip already-scanned streams:
- Python: `load_resume_data()` builds a set of hashes (scan_ads.py:227-240)
- PowerShell: Builds a hashtable from resume file (Scan-AlternateDataStreams-VT.ps1:1206-1217)

### Error Handling

- File access errors are silently ignored to allow scans to continue
- VT/HA API errors (404, 429) are handled specifically:
  - 404 = Not in database (flagged for submission)
  - 429 = Rate limit exceeded (automatic 60s wait + retry)
  - 401/403 = Authentication error (invalid API key)

## Security Considerations

**This is security analysis software** - it identifies threats but does not execute or modify streams:
- Scripts only READ alternate data streams
- No stream modification or deletion capabilities
- Output is forensic CSV/JSON/HTML/STIX reports for manual review
- API keys encrypted with user-specific DPAPI
- Only SHA256 hashes sent to APIs (not file content)

**When modifying code:**
- Never add functionality to execute or modify discovered streams
- Preserve read-only nature of all file operations
- Keep API lookups hash-only (no file submissions)
- Maintain error suppression to prevent scan interruption
- Never commit API keys or configuration files

## Testing

**Python Unit Tests** (`test_ads_scanner.py`):
```bash
python test_ads_scanner.py
```

Tests cover:
- DPAPI encryption/decryption
- Configuration management (add/remove/list keys)
- Cache operations (store/retrieve, TTL)
- Risk calculation (HIGH/MEDIUM/LOW/UNKNOWN)

**Manual Testing**:

1. Create test files with ADS:
```powershell
echo "test content" > test.txt
echo "hidden data" > test.txt:hidden
echo "secret info" > test.txt:secret
```

2. Run both implementations and compare outputs:
```bash
# Python
python scan_ads.py . --use-config --export-format html

# PowerShell
.\Scan-AlternateDataStreams-VT.ps1 -Path . -UseConfig -ExportFormat HTML
```

3. Test with known malicious hash (EICAR test file):
```
SHA256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

4. Verify feature parity:
   - Same Combined_Risk values
   - Same VT/HA responses
   - Same cache behavior
   - Same export format outputs

## Important Notes

- This codebase is for **authorized security auditing only**
- Both scripts require Windows with NTFS filesystem
- Zone.Identifier streams are legitimate (download origin tracking) - use exclude flag to reduce noise
- VirusTotal free tier limits mean large scans take multiple days (use multiple keys!)
- Results save incrementally every 10 streams to prevent data loss on interruption
- Configuration file is user-specific (DPAPI encryption tied to Windows user account)
- Cache is optional but highly recommended for large/repeated scans

## Version History

**v1.0** (Original):
- Single VirusTotal integration
- Basic CSV export
- Rate limiting
- Resume capability

**v2.0** (Current):
- Multi-service integration (VT + Hybrid Analysis)
- Multiple API keys per service with rotation
- DPAPI-encrypted configuration file
- Results caching with TTL
- Interactive setup wizard
- Configuration CLI
- Multiple export formats (CSV, JSON, HTML, STIX)
- Combined risk assessment
- Proxy support
- Logging system (Python)
- Unit tests (Python)
- 98% feature parity between Python and PowerShell

## File Structure

```
D:\ADS Scan\
├── Python Implementation (v2.0)
│   ├── scan_ads.py              # Main scanner (890 lines)
│   ├── config_manager.py           # Configuration + DPAPI (561 lines)
│   ├── api_clients.py              # VT/HA clients (327 lines)
│   ├── key_rotator.py              # Multi-key rotation (197 lines)
│   ├── cache_manager.py            # SQLite cache (224 lines)
│   ├── export_formats.py           # JSON/HTML/STIX (477 lines)
│   └── test_ads_scanner.py         # Unit tests (342 lines)
│
├── PowerShell Implementation (v2.0)
│   ├── Scan-AlternateDataStreams-VT.ps1  # Main scanner (1,550 lines)
│   ├── ADSCache.ps1                      # JSON cache (120 lines)
│   └── ADSExportFormats.ps1              # Export handlers (375 lines)
│
├── Documentation
│   ├── README_VT.md                      # User documentation
│   ├── CLAUDE.md                         # This file (developer guide)
│   ├── IMPLEMENTATION_SUMMARY.md         # v2.0 implementation details
│   └── PHASE9_COMPLETION.md              # PowerShell v2.0 completion
│
└── User Configuration (runtime)
    %LOCALAPPDATA%\ADSScanner\
    ├── config.json                       # Encrypted API keys + settings
    ├── cache\
    │   ├── results.db (Python)           # SQLite cache
    │   └── results_cache.json (PowerShell)  # JSON cache
    └── logs\
        └── scan_*.log (Python)           # Scan logs
```

## Maintenance Guidelines

### Adding a New Feature

1. **Implement in Python first** (easier to test with unit tests)
2. **Test thoroughly** with `test_ads_scanner.py`
3. **Port to PowerShell** maintaining same logic
4. **Test both implementations** with same data
5. **Compare outputs** - CSV files should be identical (except CachedResult timing)
6. **Update documentation** (README_VT.md, this file)

### Fixing a Bug

1. **Identify affected implementation** (Python, PowerShell, or both)
2. **Write test case** (if Python bug)
3. **Fix and test**
4. **Port fix to other implementation** if applicable
5. **Verify feature parity** with comparison test

### Adding a New API Service

To add a new threat intelligence service (e.g., VirusTotal, Hybrid Analysis model):

1. **Create API client class**:
   - Python: Add to `api_clients.py`
   - PowerShell: Add embedded class to main script

2. **Implement rate limiting**:
   - Track requests per minute/hour/day
   - Automatic waiting/retry on 429 errors

3. **Add to key rotator**:
   - Update `APIKeyRotator` to support new service
   - Handle service-specific rate limits

4. **Update CSV columns**:
   - Add service-specific columns (e.g., `NEWSERVICE_ThreatLevel`)
   - Update `fieldnames` list in both implementations

5. **Update combined risk calculation**:
   - Add service results to risk algorithm
   - Maintain backward compatibility

6. **Update configuration**:
   - Add service to `api_keys` section
   - Add to interactive setup wizard
   - Add to configuration CLI

7. **Update export formats**:
   - Include new service data in JSON/HTML/STIX exports

8. **Test end-to-end**:
   - Test interactive setup
   - Test API key rotation
   - Test caching
   - Test all export formats
   - Verify feature parity

## Support

For implementation questions or issues:
1. Review this CLAUDE.md file
2. Check IMPLEMENTATION_SUMMARY.md for v2.0 details
3. Check PHASE9_COMPLETION.md for PowerShell-specific info
4. Review README_VT.md for user-facing documentation
5. Run unit tests: `python test_ads_scanner.py`
6. Enable debug logging: `--log-level DEBUG` (Python) or `-Verbose` (PowerShell)

---

**Document Version**: 2.0
**Last Updated**: 2026-01-28
**Scanner Version**: 2.0.0
**Python**: 3.6+ | **PowerShell**: 5.1+
