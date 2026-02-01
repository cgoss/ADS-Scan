# Stream Extraction & Quarantine Feature

---
**📚 Documentation Navigation**
- 🏠 **[Main README](README.md)** - Getting started
- 🆕 **[What's New in v2.1](WHATS_NEW.md)** - Latest updates and changelog
- 🔑 **[API Key Management](API_KEY_MANAGEMENT.md)** - Configure and manage API keys
- 📦 **[Extraction & Quarantine](EXTRACTION_FEATURE.md)** ← You are here
- ⏭️ **[Resume Feature](RESUME_FEATURE.md)** - Resume interrupted scans
- 🏗️ **[Developer Guide](CLAUDE.md)** - Architecture and development documentation
---



## Overview

The ADS Scanner now includes powerful extraction capabilities to isolate and quarantine suspicious alternate data streams for further analysis in safe sandbox environments.

## Features

### Automatic Extraction
- Extract alternate data streams to a quarantine directory
- Preserve original file path information in metadata
- Generate SHA256-based organization for easy lookup
- Create detailed metadata sidecar files

### Selective Filtering
Choose which streams to extract based on risk assessment:

| Filter | Description | Extracts |
|--------|-------------|----------|
| `all` | Extract every detected stream | All ADS found |
| `suspicious` | Medium or high risk | Risk = MEDIUM/HIGH, VT malicious > 0, HA score >= 40 |
| `high-risk` | Only high risk streams | Risk = HIGH |
| `malicious` | Confirmed malware only | VT malicious > 0 OR HA score >= 70 |

### Quarantine Directory Structure

```
quarantine/
├── 8a3f5d92/                           # Hash prefix subdirectory
│   ├── 8a3f5d92..._{filename}_{streamname}.bin  # Extracted stream
│   └── 8a3f5d92..._{filename}_{streamname}.bin.meta.txt  # Metadata
├── b4e21a67/
│   ├── b4e21a67..._{filename}_{streamname}.bin
│   └── b4e21a67..._{filename}_{streamname}.bin.meta.txt
└── extraction_manifest.json            # JSON manifest of all extractions
```

### Metadata Sidecar Files

Each extracted stream includes a `.meta.txt` file with:

```
======================================================================
ADS EXTRACTION METADATA
======================================================================

Original File Path: C:\Users\John\Downloads\document.pdf
Stream Name: hidden_payload
Stream Size: 45312 bytes
SHA256 Hash: 8a3f5d92...
Extraction Time: 2026-01-28 15:30:45
Extracted To: quarantine/8a3f5d92/8a3f5d92...bin

======================================================================
THREAT INTELLIGENCE
======================================================================

VT_DetectionRatio: 23/70
VT_Malicious: 23
HA_ThreatScore: 85
HA_Verdict: malicious
Combined_Risk: HIGH
VT_Link: https://www.virustotal.com/gui/file/8a3f5d92...
HA_ReportURL: https://www.hybrid-analysis.com/sample/abc123
```

### Extraction Manifest

The `extraction_manifest.json` file tracks all extractions:

```json
{
  "extraction_date": "2026-01-28T15:30:45",
  "scan_path": "C:\\Users",
  "extraction_filter": "high-risk",
  "total_extracted": 12,
  "extraction_errors": 0,
  "extractions": [
    {
      "original_path": "C:\\Users\\John\\Downloads\\document.pdf",
      "stream_name": "hidden_payload",
      "extracted_path": "quarantine/8a3f5d92/8a3f5d92...bin",
      "hash": "8a3f5d92eb4f1a2c3d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c",
      "risk": "HIGH"
    }
  ]
}
```

## Usage Examples

### Extract All Streams
```bash
python scan_ads.py C:\Users --use-config --extract quarantine/
```

### Extract Only High-Risk Streams
```bash
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter high-risk
```

### Extract Confirmed Malware Only
```bash
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter malicious
```

### Extract Suspicious or Worse (Medium/High)
```bash
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter suspicious
```

### Scan + Extract + Export as JSON
```bash
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter high-risk --export-format json
```

## Analysis Workflow

1. **Scan with Extraction**:
   ```bash
   python scan_ads.py C:\Suspicious --use-config --extract quarantine/ --extract-filter malicious
   ```

2. **Review Manifest**:
   ```bash
   cat quarantine/extraction_manifest.json
   ```

3. **Analyze in Sandbox**:
   - Transfer quarantine directory to isolated analysis environment
   - Use sandbox tools (Cuckoo, ANY.RUN, etc.) to analyze extracted binaries
   - Reference metadata files for original context

4. **Take Action**:
   - Delete malicious source files based on findings
   - Update security policies
   - Report IOCs to security team

## Security Considerations

### Safe Handling
- **Always** analyze extracted streams in isolated sandbox environment
- **Never** execute extracted files on production systems
- Extracted streams may contain active malware
- Use read-only mounts when transferring quarantine data

### Permission Handling
- Extraction preserves original file permissions
- May fail on protected system files (gracefully handled)
- Extraction errors are logged but don't stop the scan

### Best Practices
1. Extract to external drive or network share
2. Use dedicated malware analysis VM
3. Keep quarantine directory encrypted
4. Delete quarantine after analysis is complete
5. Document findings in incident response tickets

## Output Example

```
[*] Starting ADS scan...
[*] Path: C:\Users
[*] Output: ADS_Report_20260128_153045.csv (CSV)
[*] VirusTotal: Enabled
[*] Hybrid Analysis: Enabled
[*] AlienVault OTX: Enabled
[*] MetaDefender: Enabled
[*] Cache: Enabled
[*] Parallel API calls: Enabled
[*] Extraction: Enabled (filter: high-risk)
[*] Quarantine directory: quarantine/

Scanning: 1245/1245 files processed
Streams found: 3842

======================================================================
Scan Complete!
======================================================================
ADS streams found:   3842
Report saved to:     ADS_Report_20260128_153045.csv

Threat Intelligence Summary:
  VirusTotal requests:   156
  VT keys used:          2
  Hybrid Analysis requests: 156
  HA keys used:          1

Cache Performance:
  Cache hits:    3686
  Cache misses:  156
  Hit rate:      95.9%

Extraction Summary:
  Streams extracted:  12
  Extraction errors:  0
  Quarantine dir:     quarantine/

Extraction manifest saved to: quarantine/extraction_manifest.json

[!!!] 12 HIGH RISK stream(s) detected:
    - malware.exe:payload
      VT: https://www.virustotal.com/gui/file/8a3f5d92...
      HA: https://www.hybrid-analysis.com/sample/abc123
    ...

======================================================================
```

## Integration with Workflows

### SIEM Integration
Export scan results as STIX format, include extraction metadata:
```bash
python scan_ads.py C:\Users --use-config --extract quarantine/ --export-format stix
```

### Incident Response
```bash
# Quick triage scan of compromised system
python scan_ads.py C:\ --use-config --extract ir_case_001/ --extract-filter malicious

# Package for forensics team
tar -czf ir_case_001_quarantine.tar.gz ir_case_001/
```

### Automated Scanning
```powershell
# Daily scheduled scan with extraction
$date = Get-Date -Format "yyyyMMdd"
python scan_ads.py C:\Users --use-config --extract "quarantine_$date" --extract-filter suspicious
```

## Troubleshooting

### "Permission denied" errors
- Some system files cannot be read
- These are logged but don't stop the scan
- Run as Administrator for full system access

### Large quarantine directory
- Filter more aggressively (use `malicious` instead of `all`)
- Clean up quarantine after analysis
- Use compression for archival

### Missing extracted files
- Check extraction manifest for errors
- Verify destination directory permissions
- Review scan logs for details

## Related Documentation

- **README.md** - General usage and features
- **API_KEY_MANAGEMENT.md** - API key configuration
- **RESUME_FEATURE.md** - Resume from previous scans
- **CLAUDE.md** - Developer and architecture documentation
