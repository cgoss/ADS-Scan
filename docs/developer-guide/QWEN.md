# ADS Scanner Project Documentation

## Project Overview

The ADS (Alternate Data Stream) Scanner is an advanced security auditing tool for scanning Windows NTFS filesystems for Alternate Data Streams (ADS) with integrated threat intelligence from VirusTotal and Hybrid Analysis. The project includes both Python and PowerShell implementations with the following key features:

- **Multi-Service Threat Intelligence**: Integrates VirusTotal and Hybrid Analysis APIs for malware detection
- **Advanced API Key Management**: Supports multiple API keys per service with automatic rotation and DPAPI encryption
- **Performance & Reliability**: Includes results caching, resume capability, incremental saving, and proxy support
- **Multiple Export Formats**: Supports CSV, JSON, HTML, and STIX 2.1 export formats
- **Rate Limiting**: Automatic handling of API rate limits with smart delays and multi-key aggregation

## Building and Running

### Prerequisites
- **Windows OS** with NTFS filesystem
- **Python 3.6+** for Python version
- **PowerShell 5.1+** or **PowerShell Core 7+** for PowerShell version
- **VirusTotal and/or Hybrid Analysis API keys** (optional but recommended)

### Python Version

#### Installation
```bash
# Clone or download the project
# All required modules are in the project directory
```

#### First-Time Setup
```bash
python scan_ads.py --setup
```

#### Configuration Management
```bash
# Initialize configuration
python scan_ads.py --config init

# Add VirusTotal API key
python scan_ads.py --config add --service virustotal --key "YOUR_VT_KEY" --tier free

# Add Hybrid Analysis API key
python scan_ads.py --config add --service hybrid-analysis --key "YOUR_HA_KEY"

# List configured keys
python scan_ads.py --config list
```

#### Scanning
```bash
# Basic scan (uses all configured services)
python scan_ads.py C:\Users --use-config

# Export as HTML
python scan_ads.py C:\Users --use-config --export-format html

# Export as JSON
python scan_ads.py C:\Users --use-config --export-format json

# Export as STIX 2.1 (for SIEM integration)
python scan_ads.py C:\Users --use-config --export-format stix

# Skip Hybrid Analysis (VT only)
python scan_ads.py C:\Users --use-config --skip-hybrid-analysis

# Use proxy
python scan_ads.py C:\Users --use-config --proxy http://proxy.company.com:8080

# Disable caching
python scan_ads.py C:\Users --use-config --no-cache

# Resume interrupted scan
python scan_ads.py C:\Users --use-config --resume ADS_Report_20260128_120000.csv
```

### PowerShell Version

#### Basic Scanning
```powershell
# Scan with VirusTotal
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -VirusTotalAPIKey "YOUR_KEY"

# Exclude Zone.Identifier streams
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Temp" -ExcludeZoneIdentifier -VirusTotalAPIKey "YOUR_KEY"

# Custom output location
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Projects" -OutputFile "C:\Reports\ads_scan.csv" -VirusTotalAPIKey "YOUR_KEY"

# Resume from previous scan
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Users" -ResumeFile "ADS_Report_VT_20260128.csv" -VirusTotalAPIKey "YOUR_KEY"

# Offline scan (no API)
.\Scan-AlternateDataStreams-VT.ps1 -Path "C:\Temp" -SkipVirusTotal
```

#### Configuration Management
```powershell
# Interactive setup
.\Scan-AlternateDataStreams-VT.ps1 -InteractiveSetup

# Add API key
.\Scan-AlternateDataStreams-VT.ps1 -ConfigAction Add -Service VirusTotal -Key "YOUR_KEY" -Tier Free

# List API keys
.\Scan-AlternateDataStreams-VT.ps1 -ConfigAction List
```

## Development Conventions

### Architecture
The project follows a modular architecture with separate modules for different concerns:
- `scan_ads.py` - Main entry point and scanning logic
- `config_manager.py` - Configuration and DPAPI encryption
- `api_clients.py` - VirusTotal and Hybrid Analysis API clients
- `key_rotator.py` - Multi-key rotation manager
- `cache_manager.py` - SQLite results cache
- `export_formats.py` - JSON, HTML, STIX exporters

### Coding Standards
- Python code follows PEP 8 style guidelines
- PowerShell code follows PowerShell best practices
- All API keys are encrypted using Windows DPAPI
- Rate limiting is handled automatically
- Results are cached to reduce redundant API calls

### Testing
Unit tests are provided in `test_ads_scanner.py` covering:
- DPAPI encryption/decryption
- Configuration management
- API key rotation logic
- Cache operations
- Risk calculation algorithms

Run tests with:
```bash
python test_ads_scanner.py
```

### Security Considerations
- API keys are encrypted using Windows DPAPI
- Only SHA256 hashes are sent to APIs (not file content)
- Scripts perform read-only operations
- No streams are executed or modified during scanning

### File Structure
```
D:\ADS Scan\
├── scan_ads.py              # Main Python scanner (v2.0)
├── Scan-AlternateDataStreams-VT.ps1  # PowerShell scanner
├── config_manager.py           # Configuration and DPAPI encryption
├── api_clients.py              # VirusTotal and Hybrid Analysis clients
├── key_rotator.py              # Multi-key rotation manager
├── cache_manager.py            # SQLite results cache
├── export_formats.py           # JSON, HTML, STIX exporters
├── test_ads_scanner.py         # Unit tests
├── README_VT.md                # Main documentation
├── CLAUDE.md                   # Developer instructions
├── ADS_Report_VT_YYYYMMDD_HHMMSS.csv  # Generated reports
└── %LOCALAPPDATA%\ADSScanner\  # User configuration directory
    ├── config.json             # Encrypted API keys and settings
    ├── cache\
    │   └── results.db          # SQLite cache database
    └── logs\
        └── scan_*.log          # Scan logs
```

## Key Features

### Multi-Service Threat Intelligence
- **VirusTotal Integration** - Hash lookups with malware detection statistics
- **Hybrid Analysis Integration** - Behavioral analysis and threat scoring
- **Combined Risk Assessment** - Intelligent risk scoring (HIGH/MEDIUM/LOW/UNKNOWN)
- **Parallel API Calls** - Query both services simultaneously for faster scans

### Advanced API Key Management
- **Multiple API Keys Per Service** - Add unlimited keys for each service
- **Automatic Key Rotation** - Switch keys automatically when rate limits hit
- **DPAPI Encryption** - API keys encrypted using Windows Data Protection API
- **Configuration File** - Persistent storage at `%LOCALAPPDATA%\ADSScanner\config.json`

### Enhanced Performance & Reliability
- **Results Caching** - SQLite-based cache reduces redundant API calls
- **Resume Capability** - Continue interrupted scans from previous reports
- **Incremental Saving** - Results saved progressively to prevent data loss
- **Proxy Support** - HTTP/HTTPS proxy configuration
- **Logging System** - Detailed logs at `%LOCALAPPDATA%\ADSScanner\logs\`

### Multiple Export Formats
- **CSV** - Traditional spreadsheet format (default)
- **JSON** - Structured data with scan metadata
- **HTML** - Interactive web report with filtering
- **STIX 2.1** - Threat intelligence sharing format for SIEM integration