# What's New in ADS Scanner v2.1

## Major Updates

### ✅ Script Renamed: `scan_ads_vt.py` → `scan_ads.py`
The script has been renamed to reflect its multi-service nature (not just VirusTotal).

**Old**: `python scan_ads_vt.py ...`
**New**: `python scan_ads.py ...`

All documentation has been updated accordingly.

---

### ✅ NEW: Stream Extraction & Quarantine Feature

Extract suspicious alternate data streams to an isolated quarantine directory for safe analysis.

#### Quick Start
```bash
# Extract all streams
python scan_ads.py C:\Users --use-config --extract quarantine/

# Extract only high-risk streams
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter high-risk

# Extract confirmed malware only
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter malicious
```

#### What Gets Extracted
- **Binary content** of the alternate data stream
- **Metadata sidecar** file with threat intelligence
- **Extraction manifest** (JSON) tracking all extracted files

#### Filter Options
| Filter | Extracts |
|--------|----------|
| `all` | Every detected stream |
| `suspicious` | Medium/High risk, VT malicious > 0, or HA score >= 40 |
| `high-risk` | Only HIGH risk streams |
| `malicious` | VT malicious > 0 OR HA threat score >= 70 |

#### Quarantine Structure
```
quarantine/
├── 8a3f5d92/
│   ├── {hash}_{filename}_{streamname}.bin      # Extracted stream
│   └── {hash}_{filename}_{streamname}.bin.meta.txt  # Metadata
├── b4e21a67/
│   └── ...
└── extraction_manifest.json                     # Complete extraction log
```

#### Use Cases
- **Incident Response**: Quickly isolate suspicious files for analysis
- **Forensics**: Preserve evidence with metadata
- **Sandbox Analysis**: Extract and analyze in safe environment
- **Malware Research**: Collect samples for research

**Documentation**: See `EXTRACTION_FEATURE.md` for complete details

---

### ✅ Integrated API Key Management

Full API key management is now built into the main script. No need for separate tools!

```bash
# Launch interactive menu
python scan_ads.py --manage
```

**Menu Options:**
1. View configured API keys
2. Add a new API key (with automatic testing)
3. Remove an API key
4. Test an API key (existing or new)
5. Update an existing API key
6. Exit

**Features:**
- Automatic key testing before saving
- Proper error handling for DPAPI decryption issues
- Support for all 5 threat intelligence services
- Keyboard interrupt (Ctrl+C) handled gracefully

---

### ✅ Fixed: AlienVault OTX API Bug

**Issue**: AlienVault OTX API was returning "unhashable type: 'dict'" error.

**Root Cause**: OTX API returns malware families as dictionaries, not strings. Code tried to create a `set()` from dicts.

**Fix**: Updated `api_clients.py` to:
- Check if malware family is dict or string
- Extract `display_name`, `name`, or `value` from dicts
- Remove duplicates without using `set()` on unhashable types

**Result**: AlienVault OTX now works perfectly! ✓

---

### ✅ GitHub Repository

Project is now on GitHub: **https://github.com/cgoss/ADS-Scan**

**.gitignore** includes:
- CSV scan results (`*.csv`)
- API keys and secrets (`config.json`, `*.key`, `.env`)
- Cache and logs (`cache/`, `logs/`, `*.db`)
- Quarantine directories (`quarantine/`, `extracted_streams/`)
- Test files (`test_*.py`)
- Python artifacts (`__pycache__/`, `*.pyc`)

---

## Updated Documentation

### New Files
- **EXTRACTION_FEATURE.md** - Complete extraction/quarantine guide
- **RESUME_FEATURE.md** - CSV resume functionality explained
- **API_KEY_MANAGEMENT.md** - Full API key management guide
- **WHATS_NEW.md** - This file!

### Updated Files
- **README.md** - Reflects extraction feature and updated script name
- **CLAUDE.md** - Architecture documentation updated
- **API_KEY_MANAGEMENT.md** - Includes integrated `--manage` mode

---

## Quick Reference

### Common Commands

```bash
# Interactive API key management
python scan_ads.py --manage

# First-time setup wizard
python scan_ads.py --setup

# Basic scan with all services
python scan_ads.py C:\Users --use-config

# Scan + Extract high-risk streams
python scan_ads.py C:\Users --use-config --extract quarantine/ --extract-filter high-risk

# Scan + Export as HTML
python scan_ads.py C:\Users --use-config --export-format html

# Resume interrupted scan
python scan_ads.py C:\Users --use-config --resume ADS_Report_20260128_071400.csv

# List configured API keys
python scan_ads.py --config list

# Add API key via CLI
python scan_ads.py --config add --service virustotal --key YOUR_KEY --tier free
```

---

## Supported Services

| Service | Rate Limits (Free) | Status |
|---------|-------------------|--------|
| **VirusTotal** | 4/min, 500/day | ✓ Working |
| **Hybrid Analysis** | 5/min, 200/hour | ✓ Working |
| **AlienVault OTX** | 1000/day | ✓ **Fixed!** |
| **MetaDefender** | 10/min | ✓ Working |
| **Any.Run** | 10/min | ✓ Working |

---

## Breaking Changes

### None!
All changes are backward compatible:
- Old `scan_ads_vt.py` references in docs updated to `scan_ads.py`
- Existing command-line arguments still work
- Configuration files remain compatible
- Old CSV files can still be used with `--resume`

---

## System Requirements

- Windows OS with NTFS filesystem
- Python 3.6 or higher
- No external dependencies (stdlib only)
- Optional: API keys for threat intelligence services

---

## Getting Help

- **General Usage**: `python scan_ads.py --help`
- **API Key Management**: `APAPI_KEY_MANAGEMENT.md`
- **Extraction Feature**: `EXTRACTION_FEATURE.md`
- **Resume Functionality**: `RESUME_FEATURE.md`
- **Architecture/Development**: `CLAUDE.md`
- **GitHub Issues**: https://github.com/cgoss/ADS-Scan/issues

---

## Next Steps

1. **Update your API keys** (if you had DPAPI issues):
   ```bash
   python scan_ads.py --manage
   # Select option 2: Add a new API key
   ```

2. **Try the extraction feature**:
   ```bash
   python scan_ads.py C:\Users --use-config --extract test_quarantine/ --extract-filter suspicious
   ```

3. **Check extraction results**:
   ```bash
   cat test_quarantine/extraction_manifest.json
   ```

4. **Explore the GitHub repository**:
   ```bash
   git clone https://github.com/cgoss/ADS-Scan.git
   cd ADS-Scan
   ```

---

## Changelog Summary

**v2.1 (2026-01-28)**
- ✨ NEW: Stream extraction/quarantine feature with filtering
- ✨ NEW: Integrated API key management menu (`--manage`)
- 🐛 FIX: AlienVault OTX malware_families unhashable dict error
- 🔧 CHANGE: Script renamed `scan_ads_vt.py` → `scan_ads.py`
- 📚 NEW: Comprehensive documentation (EXTRACTION_FEATURE.md, RESUME_FEATURE.md)
- 🚀 NEW: GitHub repository with proper .gitignore
- 📝 UPDATE: All documentation reflects new script name and features

**v2.0 (2026-01-27)**
- Multi-service threat intelligence (VT, HA, OTX, MD, Any.Run)
- Multiple API keys per service with rotation
- DPAPI encryption for API keys
- Results caching (SQLite/JSON)
- Multiple export formats (CSV, JSON, HTML, STIX 2.1)
- Resume capability
- Parallel API calls
- Proxy support

---

Enjoy the new features! 🎉
