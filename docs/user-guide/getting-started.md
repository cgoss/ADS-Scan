# Getting Started with ADS Scanner

---
**📚 Documentation Navigation**
- 🏠 **[Main README](../../README.md)** - Project overview
- 📖 **[Getting Started](getting-started.md)** ← You are here
- 🔑 **[API Key Management](api-key-management.md)** - Configure API keys
- 📦 **[Extraction Feature](extraction-feature.md)** - Quarantine suspicious streams
- ⏭️ **[Resume Feature](resume-feature.md)** - Resume interrupted scans
- 📋 **[Changelog](../changelog.md)** - What's new
- 🏗️ **[Architecture](../developer-guide/architecture.md)** - Developer documentation
---

## Installation

### Prerequisites
- Windows OS with NTFS filesystem
- Python 3.6 or higher
- No external dependencies (uses only standard library)

### Quick Install

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cgoss/ADS-Scan.git
   cd ADS-Scan
   ```

2. **Run the scanner:**
   ```bash
   python ads-scan.py --help
   ```

That's it! No dependencies to install.

## First-Time Setup

### Interactive Setup Wizard

The easiest way to get started is using the interactive setup wizard:

```bash
python ads-scan.py --setup
```

This will guide you through:
- ✅ Adding API keys for threat intelligence services
- ✅ Testing keys before saving
- ✅ Configuring default settings
- ✅ Encrypting keys with Windows DPAPI

### Quick Configuration

If you prefer command-line configuration:

```bash
# Initialize configuration
python ads-scan.py --config init

# Add VirusTotal API key
python ads-scan.py --config add --service virustotal --key YOUR_VT_KEY --tier free

# Verify it was added
python ads-scan.py --config list
```

## Your First Scan

### Basic Scan

Scan a directory with all configured services:

```bash
python ads-scan.py C:\Users\YourName\Downloads --use-config
```

### Scan with Extraction

Extract suspicious streams for analysis:

```bash
python ads-scan.py C:\Users\YourName\Downloads --use-config --extract quarantine/ --extract-filter suspicious
```

### Export as HTML

Generate an interactive HTML report:

```bash
python ads-scan.py C:\Users\YourName\Downloads --use-config --export-format html
```

## Understanding the Output

### Console Output

```
[*] Starting ADS scan...
[*] Path: C:\Users\YourName\Downloads
[*] Output: ADS_Report_20260129_120000.csv (CSV)
[*] VirusTotal: Enabled
[*] Hybrid Analysis: Enabled
[*] Cache: Enabled

Scanning: 150/150 files processed
Streams found: 245

======================================================================
Scan Complete!
======================================================================
ADS streams found:   245
Report saved to:     ADS_Report_20260129_120000.csv

[!!!] 3 HIGH RISK stream(s) detected:
    - malware.exe:payload
      VT: https://www.virustotal.com/gui/file/8a3f5d92...
```

### Report Files

Reports are saved in the current directory:
- **CSV**: `ADS_Report_YYYYMMDD_HHMMSS.csv`
- **JSON**: `ADS_Report_YYYYMMDD_HHMMSS.json`
- **HTML**: `ADS_Report_YYYYMMDD_HHMMSS.html`
- **STIX**: `ADS_Report_YYYYMMDD_HHMMSS.stix`

## Next Steps

- **[Configure more API keys](api-key-management.md)** for better threat intelligence
- **[Learn about extraction](extraction-feature.md)** to quarantine suspicious files
- **[Set up automated scans](resume-feature.md)** with resume capability
- **[Read the full documentation](../../README.md)** for advanced features

## Getting Help

- **Issues**: Report bugs at https://github.com/cgoss/ADS-Scan/issues
- **Documentation**: See [docs/](../) directory
- **Examples**: Check [examples/](../../examples/) for sample scripts

## Common Issues

### "No API keys configured"

You need to add at least one API key:
```bash
python ads-scan.py --setup
```

### "Cannot decrypt API key - encrypted by different user"

API keys are encrypted per Windows user. Re-add them from your current account:
```bash
python scripts/remove_broken_keys.py
python ads-scan.py --manage
```

### Permission Denied Errors

Some system files require administrator privileges:
```bash
# Run as Administrator
python ads-scan.py C:\ --use-config
```
