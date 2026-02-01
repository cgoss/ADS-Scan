# CSV Resume Feature

---
**📚 Documentation Navigation**
- 🏠 **[Main README](README.md)** - Getting started
- 🆕 **[What's New in v2.1](WHATS_NEW.md)** - Latest updates and changelog
- 🔑 **[API Key Management](API_KEY_MANAGEMENT.md)** - Configure and manage API keys
- 📦 **[Extraction & Quarantine](EXTRACTION_FEATURE.md)** - Extract suspicious streams for analysis
- ⏭️ **[Resume Feature](RESUME_FEATURE.md)** ← You are here
- 🏗️ **[Developer Guide](CLAUDE.md)** - Architecture and development documentation
---



## Yes! The Script Uses CSV Files for Resume Functionality

The scanner can **resume from previous CSV scan results** to skip already-scanned files, saving time and API quota.

## How It Works

### 1. Automatic CSV Creation
Every scan creates a timestamped CSV file:
```
ADS_Report_VT_20260128_071400.csv
ADS_Report_VT_20260128_071442.csv
```

### 2. CSV Contents
Each CSV contains:
- File and stream metadata
- **SHA256 hash** of each stream (used for resume)
- VirusTotal results
- Hybrid Analysis results
- AlienVault OTX results
- MetaDefender results
- Combined risk assessment

### 3. Resume from Previous Scan
```bash
# Original scan (creates CSV)
python scan_ads.py C:\Users --use-config

# Resume from previous scan (skips already-scanned hashes)
python scan_ads.py C:\Users --resume ADS_Report_VT_20260128_071400.csv --use-config
```

## Resume Logic

When you use `--resume`, the scanner:

1. **Loads previous CSV** - Extracts all SHA256 hashes from the `StreamSHA256` column
2. **Builds skip list** - Creates a set of hashes to skip
3. **Scans files** - Enumerates all alternate data streams
4. **Checks hash** - For each stream:
   - Calculates SHA256 hash
   - Checks if hash exists in skip list
   - If **found**: Skips API lookups (saves quota!)
   - If **new**: Performs full API lookups
5. **Saves results** - Creates new CSV with complete results

## Use Cases

### Continue Interrupted Scan
```bash
# Scan was interrupted (Ctrl+C, power loss, etc.)
python scan_ads.py C:\Users --use-config

# Resume where you left off
python scan_ads.py C:\Users --resume ADS_Report_VT_20260128_071400.csv --use-config
```

### Incremental Scanning
```bash
# Daily scan - only check new/modified streams
python scan_ads.py C:\Users --resume previous_scan.csv --use-config
```

### Re-scan with Different Services
```bash
# First scan with VirusTotal only
python scan_ads.py C:\Users --use-config --skip-hybrid-analysis

# Re-scan same files with Hybrid Analysis (reuses VT results from cache/CSV)
python scan_ads.py C:\Users --resume ADS_Report_VT_20260128_071400.csv --use-config
```

## Benefits

✅ **Saves API Quota** - Already-scanned hashes don't consume API requests
✅ **Faster Scans** - Skips redundant lookups
✅ **Handle Large Scans** - Scan in multiple sessions without wasting quota
✅ **Incremental Updates** - Daily scans only check new files

## CSV Files in Your Directory

You currently have these CSV files:

```
ADS_Report_VT_20260128_071400.csv  (3.0 MB)
ADS_Report_VT_20260128_071442.csv  (3.3 MB)
```

These contain previous scan results and can be used with `--resume`.

## Example Workflow

### Full Scan (Day 1)
```bash
python scan_ads.py D:\ --use-config -o d_drive_scan_day1.csv
```
Output: `d_drive_scan_day1.csv` with 10,000 streams

### Incremental Scan (Day 2)
```bash
python scan_ads.py D:\ --resume d_drive_scan_day1.csv --use-config -o d_drive_scan_day2.csv
```
- Skips 9,950 unchanged streams (from resume CSV)
- Only scans 50 new/modified streams
- Saves 9,950 API requests!

## Technical Details

### Hash Matching
The resume feature matches on **SHA256 hash** of stream contents:
- Same file + same stream name + same content = **SKIP**
- Same file + same stream name + different content = **SCAN** (file was modified)
- Different file + same hash = **SKIP** (duplicate content)

### Resume with Cache
Resume works alongside caching:
1. Check **resume CSV** - Skip if hash found
2. Check **cache database** - Skip if recent result cached
3. **Query APIs** - Only if not in resume CSV or cache

Combined, these drastically reduce API usage!

### Code Reference

Resume logic in `scan_ads.py`:
```python
# Line ~329-342: Load resume hashes
def load_resume_data(resume_file):
    """Load SHA256 hashes from previous scan CSV"""
    resume_hashes = set()
    with open(resume_file, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('StreamSHA256'):
                resume_hashes.add(row['StreamSHA256'])
    return resume_hashes

# Scanning loop checks: if stream_hash in resume_hashes: skip
```

## Best Practices

1. **Keep Recent CSVs** - Archive old scans for resume capability
2. **Use Descriptive Names** - Use `-o` to name output files meaningfully
3. **Resume After Changes** - If you add new API keys/services, resume previous scan to fill in missing data
4. **Combine with Cache** - Enable cache (default) + resume for maximum efficiency

## Example Commands

```bash
# Initial full scan
python scan_ads.py C:\Users --use-config -o users_scan_jan28.csv

# Weekly re-scan (only new files)
python scan_ads.py C:\Users --resume users_scan_jan28.csv --use-config -o users_scan_feb04.csv

# Scan another location with same resume file (shares some files)
python scan_ads.py D:\Backups --resume users_scan_jan28.csv --use-config

# Resume scan with different export format
python scan_ads.py C:\Users --resume users_scan_jan28.csv --use-config --export-format json
```

## Notes

- Resume CSV can be from any previous scan (doesn't have to match the scan path)
- Resume works with all export formats (CSV, JSON, HTML, STIX)
- Resume is independent of cache - you can use both simultaneously
- The new output CSV contains complete results (old + new)
