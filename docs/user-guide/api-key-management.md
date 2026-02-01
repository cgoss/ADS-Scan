# API Key Management Guide

---
**📚 Documentation Navigation**
- 🏠 **[Main README](README.md)** - Getting started
- 🆕 **[What's New in v2.1](WHATS_NEW.md)** - Latest updates and changelog
- 🔑 **[API Key Management](API_KEY_MANAGEMENT.md)** ← You are here
- 📦 **[Extraction & Quarantine](EXTRACTION_FEATURE.md)** - Extract suspicious streams for analysis
- ⏭️ **[Resume Feature](RESUME_FEATURE.md)** - Resume interrupted scans
- 🏗️ **[Developer Guide](CLAUDE.md)** - Architecture and development documentation
---



## Quick Start

### Interactive Management Menu (Recommended)
```bash
python scan_ads.py --manage
```

This launches a user-friendly menu with options to:
1. **View** all configured API keys
2. **Add** a new API key (with automatic testing)
3. **Remove** an API key
4. **Test** an API key (existing or new)
5. **Update** an existing API key
6. **Exit** to start scanning or quit

### First-Time Setup Wizard
```bash
python scan_ads.py --setup
```

Guides you through initial configuration of API keys and settings.

## Command-Line Management

For scripting or automation, use the CLI commands:

### Initialize Configuration
```bash
python scan_ads.py --config init
```

### Add API Keys
```bash
# VirusTotal
python scan_ads.py --config add --service virustotal --key YOUR_VT_KEY --tier free

# Hybrid Analysis
python scan_ads.py --config add --service hybrid-analysis --key YOUR_HA_KEY

# AlienVault OTX
python scan_ads.py --config add --service alienvault-otx --key YOUR_OTX_KEY

# MetaDefender
python scan_ads.py --config add --service metadefender --key YOUR_MD_KEY

# Any.Run
python scan_ads.py --config add --service any-run --key YOUR_ANYRUN_KEY
```

### List Configured Keys
```bash
python scan_ads.py --config list
```

### Remove API Key
```bash
# Remove VirusTotal key at index 0
python scan_ads.py --config remove --service virustotal --index 0
```

### Test API Key
```bash
# Test a new key before adding it
python scan_ads.py --config test --service virustotal --key YOUR_KEY
```

## Supported Services

| Service | Free Tier Limits | Notes |
|---------|------------------|-------|
| **VirusTotal** | 4 req/min, 500 req/day | Best coverage, 70+ engines |
| **Hybrid Analysis** | 5 req/min, 200 req/hour | Sandbox analysis, threat scoring |
| **AlienVault OTX** | 1000 req/day | Threat pulse intelligence |
| **MetaDefender** | 10 req/min | Multi-engine scanning |
| **Any.Run** | 10 req/min | Interactive sandbox |

## Key Features

### Automatic Testing
When adding keys, they are automatically tested before saving:
```
[*] Testing virustotal API key... SUCCESS! (4 req/min, 500 req/day)
[+] API key added for virustotal (free tier)
```

### Encryption (DPAPI)
All API keys are encrypted using Windows Data Protection API:
- Keys are encrypted per Windows user account
- Cannot be decrypted by other users
- Stored in: `%LOCALAPPDATA%\ADSScanner\config.json`

### Multi-Key Support
You can add multiple keys per service for automatic rotation:
```bash
# Add a free tier key
python scan_ads.py --config add --service virustotal --key KEY1 --tier free

# Add a paid tier key with higher priority
python scan_ads.py --config add --service virustotal --key KEY2 --tier paid
```

The scanner will automatically rotate between keys when rate limits are reached.

## Troubleshooting

### "Cannot decrypt API key - encrypted by different user"

**Problem**: API keys were added by a different Windows user account.

**Solution**: Remove and re-add the keys from your current account:
```bash
# Remove broken keys
python scan_ads.py --config remove --service virustotal --index 0

# Add keys again
python scan_ads.py --manage
# Select option 2: Add a new API key
```

Or use the automatic cleanup tool:
```bash
python remove_broken_keys.py
```

### Diagnostic Tools

Check which keys can be decrypted:
```bash
python diagnose_keys.py
```

Remove all broken keys automatically:
```bash
python remove_broken_keys.py
```

## Configuration File Location

- **Windows**: `%LOCALAPPDATA%\ADSScanner\config.json`
- **Example**: `C:\Users\YourName\AppData\Local\ADSScanner\config.json`

## Usage Examples

### Manage Keys Interactively
```bash
# Launch interactive manager
python scan_ads.py --manage

# Select option 1 to view current keys
# Select option 2 to add a new key
# Select option 4 to test existing keys
# Select option 6 to exit
```

### Quick Add via CLI
```bash
# Add VirusTotal key and start scanning
python scan_ads.py --config add --service virustotal --key YOUR_KEY --tier free
python scan_ads.py C:\Users --use-config
```

### Scan with Configured Keys
```bash
# Use all configured keys
python scan_ads.py C:\Users --use-config

# Use configured keys but skip Hybrid Analysis
python scan_ads.py C:\Users --use-config --skip-hybrid-analysis

# Export as JSON
python scan_ads.py C:\Users --use-config --export-format json
```

## Best Practices

1. **Use Interactive Menu** (`--manage`) for initial setup and testing
2. **Test Keys Before Adding** using the built-in test function
3. **Add Multiple Keys** per service for better rate limit handling
4. **Set Priority** (1=highest) for paid tier keys to use them first
5. **Regular Testing** to ensure keys are still valid
6. **Backup Config** before making bulk changes

## Security Notes

- API keys are encrypted using Windows DPAPI
- Keys are user-specific and cannot be shared between Windows accounts
- Config file can be safely backed up (keys remain encrypted)
- Never commit plaintext API keys to version control
