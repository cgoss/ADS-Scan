#!/usr/bin/env python3
"""
NTFS Alternate Data Stream Scanner with Multi-Service Threat Intelligence
Version 2.0

Scans for NTFS Alternate Data Streams with VirusTotal and Hybrid Analysis integration,
supporting multiple API keys per service with automatic rotation, results caching,
and multiple export formats (CSV, JSON, HTML, STIX).

Requirements:
    - Windows OS with NTFS filesystem
    - Python 3.6+
    - No external dependencies (uses only standard library)

Usage:
    # Configuration management
    python scan_ads_vt.py --config init
    python scan_ads_vt.py --config add --service virustotal --key YOUR_KEY --tier free
    python scan_ads_vt.py --config list

    # Interactive setup (first run)
    python scan_ads_vt.py --setup

    # Scanning with configuration file
    python scan_ads_vt.py C:\\Users --use-config

    # Scanning with command-line API keys (legacy mode)
    python scan_ads_vt.py C:\\Users --api-key YOUR_VT_KEY

    # Export formats
    python scan_ads_vt.py C:\\Users --use-config --export-format json
    python scan_ads_vt.py C:\\Users --use-config --export-format html
"""

import os
import sys
import csv
import json
import argparse
import hashlib
import time
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import ctypes
from ctypes import wintypes

# Import new modules
try:
    from config_manager import ConfigManager
    from api_clients import VirusTotalAPI, HybridAnalysisAPI
    from key_rotator import APIKeyRotator
    from cache_manager import CacheManager
    from export_formats import (
        export_to_csv, export_to_json, export_to_html, export_to_stix,
        calculate_combined_risk
    )
except ImportError as e:
    print(f"ERROR: Failed to import required modules: {e}")
    print("Ensure all scanner modules are in the same directory.")
    sys.exit(1)

# Windows API constants
INVALID_HANDLE_VALUE = -1
ERROR_HANDLE_EOF = 38

# Windows API structures
class WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ("StreamSize", wintypes.LARGE_INTEGER),
        ("cStreamName", wintypes.WCHAR * 296)
    ]

# Load Windows API functions
try:
    kernel32 = ctypes.windll.kernel32

    FindFirstStreamW = kernel32.FindFirstStreamW
    FindFirstStreamW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.POINTER(WIN32_FIND_STREAM_DATA),
        wintypes.DWORD
    ]
    FindFirstStreamW.restype = wintypes.HANDLE

    FindNextStreamW = kernel32.FindNextStreamW
    FindNextStreamW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(WIN32_FIND_STREAM_DATA)
    ]
    FindNextStreamW.restype = wintypes.BOOL

    FindClose = kernel32.FindClose
    FindClose.argtypes = [wintypes.HANDLE]
    FindClose.restype = wintypes.BOOL

except (AttributeError, OSError):
    print("ERROR: This script requires Windows OS with NTFS support.")
    sys.exit(1)


def setup_logging(log_dir: Path, log_level: str = "INFO") -> logging.Logger:
    """Setup logging to file and console"""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )

    logger = logging.getLogger('ads_scanner')
    logger.info(f"Logging initialized: {log_file}")
    return logger


def get_alternate_streams(file_path):
    """Get all alternate data streams for a file using Windows API"""
    streams = []
    find_stream_data = WIN32_FIND_STREAM_DATA()

    try:
        handle = FindFirstStreamW(
            file_path,
            0,  # FindStreamInfoStandard
            ctypes.byref(find_stream_data),
            0
        )

        if handle == INVALID_HANDLE_VALUE:
            return streams

        try:
            while True:
                stream_name = find_stream_data.cStreamName
                stream_size = find_stream_data.StreamSize

                if stream_name and stream_name != "::$DATA":
                    clean_name = stream_name.lstrip(':').replace(':$DATA', '')
                    streams.append((clean_name, stream_size))

                if not FindNextStreamW(handle, ctypes.byref(find_stream_data)):
                    break
        finally:
            FindClose(handle)
    except Exception:
        pass

    return streams


def compute_sha256(file_path, stream_name):
    """Compute SHA256 hash of a stream"""
    try:
        stream_path = f"{file_path}:{stream_name}"
        sha256 = hashlib.sha256()

        with open(stream_path, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                sha256.update(data)

        return sha256.hexdigest()
    except Exception:
        return ""


def read_stream_preview(file_path, stream_name, max_bytes=100):
    """Read a preview of the stream content"""
    try:
        stream_path = f"{file_path}:{stream_name}"

        with open(stream_path, 'rb') as f:
            content = f.read(max_bytes)

        if not content:
            return "Empty", ""

        # Check if content appears to be text
        is_text = True
        for byte in content:
            if byte == 0 or (byte < 32 and byte not in [9, 10, 13]):
                is_text = False
                break

        if is_text:
            try:
                text_content = content.decode('utf-8', errors='ignore')
                return "Text", text_content[:200]
            except:
                text_content = content.decode('ascii', errors='ignore')
                return "Text", text_content[:200]
        else:
            hex_content = ' '.join(f'{b:02X}' for b in content[:50])
            return "Binary", hex_content

    except Exception as e:
        return "Unknown", f"Unable to read: {str(e)}"


def get_file_info(file_path):
    """Get file metadata"""
    try:
        stat_info = os.stat(file_path)
        return {
            'size': stat_info.st_size,
            'created': datetime.fromtimestamp(stat_info.st_ctime),
            'modified': datetime.fromtimestamp(stat_info.st_mtime),
            'accessed': datetime.fromtimestamp(stat_info.st_atime)
        }
    except:
        return {
            'size': 0,
            'created': '',
            'modified': '',
            'accessed': ''
        }


def load_resume_data(resume_file):
    """Load previously scanned hashes from a resume file"""
    scanned_hashes = set()
    try:
        with open(resume_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get('StreamSHA256'):
                    scanned_hashes.add(row['StreamSHA256'])
        print(f"[+] Loaded {len(scanned_hashes)} previously scanned hashes from resume file")
    except Exception as e:
        print(f"[!] Error loading resume file: {e}")

    return scanned_hashes


def lookup_hash_parallel(file_hash, vt_rotator, ha_rotator, otx_rotator, metadefender_rotator, cache_mgr, logger):
    """Query all services in parallel with caching"""
    # Check cache first
    if cache_mgr and cache_mgr.has_result(file_hash):
        cached = cache_mgr.get_result(file_hash)
        if cached:
            logger.debug(f"Cache hit for hash: {file_hash[:16]}...")
            return cached

    results = {'vt': None, 'ha': None, 'otx': None, 'metadefender': None, 'from_cache': False}

    # Query all services in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}

        if vt_rotator and vt_rotator.has_available_keys():
            futures[executor.submit(vt_rotator.lookup_hash, file_hash)] = 'vt'

        if ha_rotator and ha_rotator.has_available_keys():
            futures[executor.submit(ha_rotator.lookup_hash, file_hash)] = 'ha'

        if otx_rotator and otx_rotator.has_available_keys():
            futures[executor.submit(otx_rotator.lookup_hash, file_hash)] = 'otx'

        if metadefender_rotator and metadefender_rotator.has_available_keys():
            futures[executor.submit(metadefender_rotator.lookup_hash, file_hash)] = 'metadefender'

        for future in as_completed(futures):
            service = futures[future]
            try:
                results[service] = future.result()
            except Exception as e:
                logger.error(f"Error querying {service}: {e}")
                results[service] = None

    # Cache results
    if cache_mgr:
        cache_mgr.store_result(file_hash, results)

    return results


def scan_path(root_path, exclude_zone_identifier, vt_rotator, ha_rotator,
              otx_rotator, metadefender_rotator, cache_mgr, resume_hashes, logger, parallel_api_calls=True):
    """Recursively scan a path for files with alternate data streams"""
    file_count = 0
    ads_count = 0
    stats = {
        'vt_not_found': 0,
        'vt_malicious': 0,
        'ha_malicious': 0,
        'high_risk': 0,
        'medium_risk': 0,
        'low_risk': 0,
        'unknown_risk': 0
    }

    if resume_hashes is None:
        resume_hashes = set()

    print(f"\n[*] Scanning path: {root_path}")
    print("=" * 70)

    for root, dirs, files in os.walk(root_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            file_count += 1

            if file_count % 100 == 0:
                print(f"[*] Scanned {file_count} files, found {ads_count} ADS "
                      f"(High risk: {stats['high_risk']}, Medium: {stats['medium_risk']})...", end='\r')

            try:
                streams = get_alternate_streams(file_path)

                for stream_name, stream_size in streams:
                    if exclude_zone_identifier and stream_name == "Zone.Identifier":
                        continue

                    ads_count += 1
                    file_info = get_file_info(file_path)
                    stream_hash = compute_sha256(file_path, stream_name)

                    if stream_hash in resume_hashes:
                        continue

                    stream_type, stream_preview = read_stream_preview(file_path, stream_name)

                    # API lookups
                    vt_result = None
                    ha_result = None
                    otx_result = None
                    metadefender_result = None
                    cached = False
                    api_keys_used = []

                    if stream_hash and (vt_rotator or ha_rotator or otx_rotator or metadefender_rotator):
                        print(f"\n[{ads_count}] Checking: {filename}:{stream_name}")
                        print(f"    SHA256: {stream_hash}")

                        if parallel_api_calls:
                            # Parallel lookup
                            api_results = lookup_hash_parallel(
                                stream_hash, vt_rotator, ha_rotator, otx_rotator, metadefender_rotator, cache_mgr, logger
                            )
                            vt_result = api_results.get('vt')
                            ha_result = api_results.get('ha')
                            otx_result = api_results.get('otx')
                            metadefender_result = api_results.get('metadefender')
                            cached = api_results.get('from_cache', False)

                            if cached:
                                print(f"    [CACHE] Results from cache")
                        else:
                            # Sequential lookup
                            if vt_rotator:
                                vt_result = vt_rotator.lookup_hash(stream_hash)
                                if vt_result:
                                    api_keys_used.append("VT")

                            if ha_rotator:
                                ha_result = ha_rotator.lookup_hash(stream_hash)
                                if ha_result:
                                    api_keys_used.append("HA")

                            if otx_rotator:
                                otx_result = otx_rotator.lookup_hash(stream_hash)
                                if otx_result:
                                    api_keys_used.append("OTX")

                            if metadefender_rotator:
                                metadefender_result = metadefender_rotator.lookup_hash(stream_hash)
                                if metadefender_result:
                                    api_keys_used.append("MD")

                        # Display results
                        if vt_result:
                            if not vt_result['found']:
                                stats['vt_not_found'] += 1
                                print(f"    [VT] NOT IN DATABASE")
                            elif vt_result['malicious'] > 0:
                                stats['vt_malicious'] += 1
                                print(f"    [VT] MALICIOUS: {vt_result['detection_ratio']}")
                            else:
                                print(f"    [VT] Clean: {vt_result['detection_ratio']}")

                        if ha_result:
                            if not ha_result['found']:
                                print(f"    [HA] NOT IN DATABASE")
                            elif ha_result['threat_score'] >= 70:
                                stats['ha_malicious'] += 1
                                print(f"    [HA] MALICIOUS: Score {ha_result['threat_score']} ({ha_result['verdict']})")
                            elif ha_result['threat_score'] >= 40:
                                print(f"    [HA] SUSPICIOUS: Score {ha_result['threat_score']} ({ha_result['verdict']})")
                            else:
                                print(f"    [HA] Clean: Score {ha_result['threat_score']}")

                        if otx_result:
                            if not otx_result['found']:
                                print(f"    [OTX] NOT IN DATABASE")
                            elif otx_result['reputation'] >= 50:
                                print(f"    [OTX] MALICIOUS: Reputation {otx_result['reputation']}, {otx_result['pulse_count']} pulses")
                            elif otx_result['reputation'] >= 20:
                                print(f"    [OTX] SUSPICIOUS: Reputation {otx_result['reputation']}, {otx_result['pulse_count']} pulses")
                            else:
                                print(f"    [OTX] Clean: Reputation {otx_result['reputation']}, {otx_result['pulse_count']} pulses")

                        if metadefender_result:
                            if not metadefender_result['found']:
                                print(f"    [MD] NOT IN DATABASE")
                            elif metadefender_result['detected'] > 0:
                                print(f"    [MD] MALICIOUS: {metadefender_result['detection_ratio']}")
                            else:
                                print(f"    [MD] Clean: {metadefender_result['detection_ratio']}")

                        # Calculate combined risk
                        combined_risk = calculate_combined_risk(vt_result, ha_result, otx_result, metadefender_result)
                        stats[f'{combined_risk.lower()}_risk'] += 1

                        if combined_risk == 'HIGH':
                            print(f"    [!!!] COMBINED RISK: HIGH")
                        elif combined_risk == 'MEDIUM':
                            print(f"    [!] COMBINED RISK: MEDIUM")

                    # Build result dictionary
                    result = {
                        'FilePath': file_path,
                        'FileName': filename,
                        'FileSize': file_info['size'],
                        'FileExtension': Path(filename).suffix,
                        'FileCreated': file_info['created'],
                        'FileModified': file_info['modified'],
                        'FileAccessed': file_info['accessed'],
                        'StreamName': stream_name,
                        'StreamSize': stream_size,
                        'StreamType': stream_type,
                        'StreamSHA256': stream_hash,
                        'StreamPreview': stream_preview,

                        # VirusTotal results
                        'VT_Found': vt_result['found'] if vt_result else 'N/A',
                        'VT_DetectionRatio': vt_result['detection_ratio'] if vt_result else 'N/A',
                        'VT_Malicious': vt_result['malicious'] if vt_result else 'N/A',
                        'VT_Suspicious': vt_result['suspicious'] if vt_result else 'N/A',
                        'VT_Undetected': vt_result['undetected'] if vt_result else 'N/A',
                        'VT_Harmless': vt_result['harmless'] if vt_result else 'N/A',
                        'VT_DetectionEngines': vt_result['detection_engines'] if vt_result else 'N/A',
                        'VT_ScanDate': vt_result['scan_date'] if vt_result else 'N/A',
                        'VT_Link': vt_result['link'] if vt_result else 'N/A',

                        # Hybrid Analysis results
                        'HA_Found': ha_result['found'] if ha_result else 'N/A',
                        'HA_ThreatScore': ha_result['threat_score'] if ha_result else 'N/A',
                        'HA_Verdict': ha_result['verdict'] if ha_result else 'N/A',
                        'HA_AVDetect': ha_result['av_detect'] if ha_result else 'N/A',
                        'HA_VXFamily': ha_result['vx_family'] if ha_result else 'N/A',
                        'HA_JobID': ha_result['job_id'] if ha_result else 'N/A',
                        'HA_ReportURL': ha_result['report_url'] if ha_result else 'N/A',
                        'HA_ScanDate': ha_result['scan_date'] if ha_result else 'N/A',

                        # AlienVault OTX results
                        'OTX_Found': otx_result['found'] if otx_result else 'N/A',
                        'OTX_PulseCount': otx_result['pulse_count'] if otx_result else 'N/A',
                        'OTX_MalwareFamilies': '; '.join(otx_result['malware_families']) if otx_result and otx_result['malware_families'] else 'N/A',
                        'OTX_Reputation': otx_result['reputation'] if otx_result else 'N/A',
                        'OTX_Link': otx_result['otx_link'] if otx_result else 'N/A',

                        # MetaDefender results
                        'MetaDefender_Found': metadefender_result['found'] if metadefender_result else 'N/A',
                        'MetaDefender_DetectionRatio': metadefender_result['detection_ratio'] if metadefender_result else 'N/A',
                        'MetaDefender_Detected': metadefender_result['detected'] if metadefender_result else 'N/A',
                        'MetaDefender_TotalEngines': metadefender_result['total_engines'] if metadefender_result else 'N/A',
                        'MetaDefender_ScanAllResult': metadefender_result['scan_all_result'] if metadefender_result else 'N/A',
                        'MetaDefender_Link': metadefender_result['metadefender_link'] if metadefender_result else 'N/A',

                        # Combined analysis
                        'Combined_Risk': combined_risk if (vt_result or ha_result or otx_result or metadefender_result) else 'UNKNOWN',
                        'FlagForSubmission': 'YES' if (
                            (vt_result and not vt_result['found']) or
                            (ha_result and not ha_result['found']) or
                            (otx_result and not otx_result['found']) or
                            (metadefender_result and not metadefender_result['found'])
                        ) else 'NO',

                        # Metadata
                        'CachedResult': 'YES' if cached else 'NO',
                        'APIKeysUsed': ','.join(api_keys_used),
                        'ScanDate': datetime.now()
                    }

                    yield result

            except Exception as e:
                logger.debug(f"Error scanning {file_path}: {e}")
                continue

    print(f"\n[+] Scan complete: {file_count} files, {ads_count} ADS found")
    print(f"[+] Risk summary: {stats['high_risk']} HIGH, {stats['medium_risk']} MEDIUM, "
          f"{stats['low_risk']} LOW, {stats['unknown_risk']} UNKNOWN")


def interactive_setup(config_mgr):
    """Interactive setup for first-run configuration"""
    print("\n" + "=" * 70)
    print("Welcome to ADS Scanner with Threat Intelligence")
    print("=" * 70)
    print("\nNo configuration file found. Let's set up your API keys.\n")

    # VirusTotal setup
    vt_configure = input("Configure VirusTotal? (y/n): ").strip().lower()
    if vt_configure == 'y':
        while True:
            vt_key = input("  Enter VirusTotal API key: ").strip()
            if not vt_key:
                break

            tier = input("  Tier (free/paid) [free]: ").strip().lower() or "free"

            print("  Testing key...", end='', flush=True)
            test_result = config_mgr.test_api_key('virustotal', vt_key)

            if test_result['success']:
                print(f" SUCCESS! ({test_result['tier_info']})")
                config_mgr.add_api_key('virustotal', vt_key, tier=tier, priority=1)
            else:
                print(f" FAILED: {test_result['message']}")
                continue

            another = input("  Add another VT key? (y/n): ").strip().lower()
            if another != 'y':
                break

    # Hybrid Analysis setup
    ha_configure = input("\nConfigure Hybrid Analysis? (y/n): ").strip().lower()
    if ha_configure == 'y':
        while True:
            ha_key = input("  Enter Hybrid Analysis API key: ").strip()
            if not ha_key:
                break

            print("  Testing key...", end='', flush=True)
            test_result = config_mgr.test_api_key('hybrid_analysis', ha_key)

            if test_result['success']:
                print(f" SUCCESS! ({test_result['tier_info']})")
                config_mgr.add_api_key('hybrid_analysis', ha_key, priority=1)
            else:
                print(f" FAILED: {test_result['message']}")
                continue

            another = input("  Add another HA key? (y/n): ").strip().lower()
            if another != 'y':
                break

    # Additional settings
    print("\nAdditional settings:")
    exclude_zone = input("  Exclude Zone.Identifier streams? (y/n) [y]: ").strip().lower() or 'y'
    config_mgr.set_setting('exclude_zone_identifier', exclude_zone == 'y')

    cache_enabled = input("  Enable results caching? (y/n) [y]: ").strip().lower() or 'y'
    config_mgr.set_setting('cache_enabled', cache_enabled == 'y')

    if cache_enabled == 'y':
        cache_ttl = input("  Cache TTL (days) [7]: ").strip() or "7"
        config_mgr.set_setting('cache_ttl_days', int(cache_ttl))

    proxy = input("  Proxy URL (or Enter for none): ").strip()
    if proxy:
        config_mgr.set_setting('proxy', proxy)

    print(f"\n[+] Configuration saved to: {config_mgr.config_file}")
    print("[+] API keys encrypted using Windows DPAPI (current user only)")
    print("\n[+] Ready to scan! Run with --help for usage.\n")


def manage_keys_interactive(config_mgr):
    """Interactive API key management menu"""
    print("\n" + "=" * 70)
    print("           ADS Scanner v2.1 - API Key Manager")
    print("=" * 70)
    print()

    while True:
        print("\nAPI Key Management Menu:")
        print("1. View configured API keys")
        print("2. Add a new API key")
        print("3. Remove an API key")
        print("4. Test an API key")
        print("5. Update an existing API key")
        print("6. Exit (start scanning or quit)")
        print()

        try:
            choice = input("Enter your choice (1-6): ").strip()

            if choice == '1':
                display_keys_menu(config_mgr)
            elif choice == '2':
                add_key_menu(config_mgr)
            elif choice == '3':
                remove_key_menu(config_mgr)
            elif choice == '4':
                test_key_menu(config_mgr)
            elif choice == '5':
                update_key_menu(config_mgr)
            elif choice == '6':
                print("\n[+] Exiting key management...\n")
                break
            else:
                print("\n[!] Invalid choice. Please enter a number between 1 and 6.")

        except KeyboardInterrupt:
            print("\n\n[+] Exiting key management...\n")
            break
        except EOFError:
            print("\n\n[+] Exiting key management...\n")
            break


def display_keys_menu(config_mgr):
    """Display all configured API keys"""
    print("\n" + "=" * 70)
    print("Configured API Keys")
    print("=" * 70)

    all_keys = config_mgr.list_api_keys()
    has_keys = False

    for service in ['virustotal', 'hybrid_analysis', 'alienvault_otx', 'metadefender', 'any_run']:
        if all_keys.get(service):
            has_keys = True
            print(f"\n{service.upper().replace('_', ' ')}:")
            for key_info in all_keys[service]:
                status = "ENABLED" if key_info['enabled'] else "DISABLED"
                print(f"  [{key_info['index']}] {key_info['key']} "
                      f"(Tier: {key_info['tier']}, Priority: {key_info['priority']}, Status: {status})")

    if not has_keys:
        print("\nNo API keys configured.")

    print("=" * 70)


def add_key_menu(config_mgr):
    """Interactive menu to add a new API key"""
    print("\n" + "=" * 70)
    print("Add New API Key")
    print("=" * 70)

    service_map = {
        '1': ('virustotal', 'VirusTotal'),
        '2': ('hybrid_analysis', 'Hybrid Analysis'),
        '3': ('alienvault_otx', 'AlienVault OTX'),
        '4': ('metadefender', 'MetaDefender'),
        '5': ('any_run', 'Any.Run')
    }

    print("\nSelect service:")
    for key, (_, name) in service_map.items():
        print(f"{key}. {name}")

    try:
        service_choice = input("\nEnter choice (1-5): ").strip()
        if service_choice not in service_map:
            print("[!] Invalid choice")
            return

        service, service_name = service_map[service_choice]

        api_key = input(f"\nEnter {service_name} API key: ").strip()
        if not api_key:
            print("[!] API key cannot be empty")
            return

        # Get tier for applicable services
        tier = 'free'
        if service in ['virustotal', 'alienvault_otx', 'metadefender', 'any_run']:
            tier_input = input("Enter tier (free/paid) [free]: ").strip().lower()
            if tier_input in ['free', 'paid']:
                tier = tier_input

        # Get priority
        priority = 99
        priority_input = input("Enter priority (1-99, lower = higher priority) [99]: ").strip()
        if priority_input:
            try:
                priority = int(priority_input)
                if not 1 <= priority <= 99:
                    print("[!] Priority must be between 1-99, using default 99")
                    priority = 99
            except ValueError:
                print("[!] Invalid priority, using default 99")
                priority = 99

        # Test the key
        print(f"\n[*] Testing {service_name} API key...", end='', flush=True)
        test_result = config_mgr.test_api_key(service, api_key)

        if test_result['success']:
            print(f" SUCCESS! ({test_result['tier_info']})")
            config_mgr.add_api_key(service, api_key, tier=tier, priority=priority)
            print(f"\n[+] API key added successfully for {service_name}!")
            display_keys_menu(config_mgr)
        else:
            print(f" FAILED: {test_result['message']}")
            print("[!] API key was not added")

    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled")


def remove_key_menu(config_mgr):
    """Interactive menu to remove an API key"""
    print("\n" + "=" * 70)
    print("Remove API Key")
    print("=" * 70)

    display_keys_menu(config_mgr)

    service_map = {
        '1': ('virustotal', 'VirusTotal'),
        '2': ('hybrid_analysis', 'Hybrid Analysis'),
        '3': ('alienvault_otx', 'AlienVault OTX'),
        '4': ('metadefender', 'MetaDefender'),
        '5': ('any_run', 'Any.Run')
    }

    print("\nSelect service:")
    for key, (_, name) in service_map.items():
        print(f"{key}. {name}")

    try:
        service_choice = input("\nEnter choice (1-5): ").strip()
        if service_choice not in service_map:
            print("[!] Invalid choice")
            return

        service, service_name = service_map[service_choice]

        keys = config_mgr.list_api_keys(service)[service]
        if not keys:
            print(f"\n[!] No {service_name} keys configured")
            return

        print(f"\nAvailable {service_name} keys:")
        for key_info in keys:
            print(f"  [{key_info['index']}] {key_info['key']}")

        index_input = input(f"\nEnter the index of the key to remove (0-{len(keys)-1}): ").strip()
        index = int(index_input)

        if not 0 <= index < len(keys):
            print(f"[!] Invalid index")
            return

        confirm = input(f"\nAre you sure you want to remove key [{index}]? (yes/no): ").strip().lower()
        if confirm not in ['yes', 'y']:
            print("[!] Removal cancelled")
            return

        config_mgr.remove_api_key(service, index)
        print(f"\n[+] API key removed successfully from {service_name}!")
        display_keys_menu(config_mgr)

    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled")
    except (ValueError, IndexError):
        print("\n[!] Invalid input")


def test_key_menu(config_mgr):
    """Interactive menu to test an API key"""
    print("\n" + "=" * 70)
    print("Test API Key")
    print("=" * 70)

    print("\nHow would you like to test?")
    print("1. Test an existing configured API key")
    print("2. Test a new API key (enter manually)")

    try:
        mode_choice = input("\nEnter choice (1-2): ").strip()

        if mode_choice == '1':
            test_existing_key_menu(config_mgr)
        elif mode_choice == '2':
            test_new_key_menu(config_mgr)
        else:
            print("[!] Invalid choice")

    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled")


def test_existing_key_menu(config_mgr):
    """Test an existing configured API key"""
    service_map = {
        '1': ('virustotal', 'VirusTotal'),
        '2': ('hybrid_analysis', 'Hybrid Analysis'),
        '3': ('alienvault_otx', 'AlienVault OTX'),
        '4': ('metadefender', 'MetaDefender'),
        '5': ('any_run', 'Any.Run')
    }

    print("\nSelect service:")
    for key, (_, name) in service_map.items():
        print(f"{key}. {name}")

    try:
        service_choice = input("\nEnter choice (1-5): ").strip()
        if service_choice not in service_map:
            print("[!] Invalid choice")
            return

        service, service_name = service_map[service_choice]

        keys = config_mgr.list_api_keys(service)[service]
        if not keys:
            print(f"\n[!] No {service_name} keys configured")
            return

        print(f"\nAvailable {service_name} keys:")
        for key_info in keys:
            status = "ENABLED" if key_info['enabled'] else "DISABLED"
            print(f"  [{key_info['index']}] {key_info['key']} (Status: {status})")

        index_input = input(f"\nEnter the index of the key to test (0-{len(keys)-1}): ").strip()
        index = int(index_input)

        if not 0 <= index < len(keys):
            print(f"[!] Invalid index")
            return

        print(f"\n[*] Decrypting {service_name} API key [index {index}]...", end='', flush=True)

        try:
            decrypted_keys = config_mgr.get_api_keys(service)
            if index >= len(decrypted_keys):
                print(f" FAILED!")
                print(f"[!] Key index {index} not found in decrypted keys list")
                return

            decrypted_key = decrypted_keys[index]['key']
            print(" OK")

        except RuntimeError as e:
            print(f" FAILED!")
            if "DPAPI" in str(e):
                print(f"[!] Cannot decrypt API key - it was encrypted by a different Windows user")
                print(f"[!] You must add the API key again from this user account")
            else:
                print(f"[!] Decryption error: {e}")
            return
        except Exception as e:
            print(f" FAILED!")
            print(f"[!] Error decrypting API key: {e}")
            return

        print(f"[*] Testing {service_name} API key...", end='', flush=True)
        test_result = config_mgr.test_api_key(service, decrypted_key)

        if test_result['success']:
            print(f" SUCCESS!")
            print(f"\n[+] {test_result['message']}")
            print(f"[+] Rate limits: {test_result['tier_info']}")
        else:
            print(f" FAILED!")
            print(f"\n[!] {test_result['message']}")

    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled")
    except (ValueError, IndexError):
        print("\n[!] Invalid input")


def test_new_key_menu(config_mgr):
    """Test a new API key entered manually"""
    service_map = {
        '1': ('virustotal', 'VirusTotal'),
        '2': ('hybrid_analysis', 'Hybrid Analysis'),
        '3': ('alienvault_otx', 'AlienVault OTX'),
        '4': ('metadefender', 'MetaDefender'),
        '5': ('any_run', 'Any.Run')
    }

    print("\nSelect service:")
    for key, (_, name) in service_map.items():
        print(f"{key}. {name}")

    try:
        service_choice = input("\nEnter choice (1-5): ").strip()
        if service_choice not in service_map:
            print("[!] Invalid choice")
            return

        service, service_name = service_map[service_choice]

        api_key = input(f"\nEnter {service_name} API key to test: ").strip()
        if not api_key:
            print("[!] API key cannot be empty")
            return

        print(f"\n[*] Testing {service_name} API key...", end='', flush=True)
        test_result = config_mgr.test_api_key(service, api_key)

        if test_result['success']:
            print(f" SUCCESS!")
            print(f"\n[+] {test_result['message']}")
            print(f"[+] Rate limits: {test_result['tier_info']}")
        else:
            print(f" FAILED!")
            print(f"\n[!] {test_result['message']}")

    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled")


def update_key_menu(config_mgr):
    """Interactive menu to update an existing API key"""
    print("\n" + "=" * 70)
    print("Update Existing API Key")
    print("=" * 70)

    display_keys_menu(config_mgr)

    service_map = {
        '1': ('virustotal', 'VirusTotal'),
        '2': ('hybrid_analysis', 'Hybrid Analysis'),
        '3': ('alienvault_otx', 'AlienVault OTX'),
        '4': ('metadefender', 'MetaDefender'),
        '5': ('any_run', 'Any.Run')
    }

    print("\nSelect service:")
    for key, (_, name) in service_map.items():
        print(f"{key}. {name}")

    try:
        service_choice = input("\nEnter choice (1-5): ").strip()
        if service_choice not in service_map:
            print("[!] Invalid choice")
            return

        service, service_name = service_map[service_choice]

        keys = config_mgr.list_api_keys(service)[service]
        if not keys:
            print(f"\n[!] No {service_name} keys configured")
            return

        print(f"\nAvailable {service_name} keys:")
        for key_info in keys:
            print(f"  [{key_info['index']}] {key_info['key']} (Tier: {key_info['tier']}, Priority: {key_info['priority']})")

        index_input = input(f"\nEnter the index of the key to update (0-{len(keys)-1}): ").strip()
        index = int(index_input)

        if not 0 <= index < len(keys):
            print(f"[!] Invalid index")
            return

        # Get new API key
        new_api_key = input(f"\nEnter new {service_name} API key: ").strip()
        if not new_api_key:
            print("[!] API key cannot be empty")
            return

        # Get new tier
        tier = keys[index]['tier']
        if service in ['virustotal', 'alienvault_otx', 'metadefender', 'any_run']:
            tier_input = input(f"Enter new tier (free/paid) [{tier}]: ").strip().lower()
            if tier_input in ['free', 'paid']:
                tier = tier_input

        # Get new priority
        priority = keys[index]['priority']
        priority_input = input(f"Enter new priority (1-99) [{priority}]: ").strip()
        if priority_input:
            try:
                priority = int(priority_input)
                if not 1 <= priority <= 99:
                    print("[!] Priority must be between 1-99, using existing value")
                    priority = keys[index]['priority']
            except ValueError:
                print("[!] Invalid priority, using existing value")

        # Test the new key
        print(f"\n[*] Testing new {service_name} API key...", end='', flush=True)
        test_result = config_mgr.test_api_key(service, new_api_key)

        if test_result['success']:
            print(f" SUCCESS! ({test_result['tier_info']})")

            # Remove old key and add new one
            config_mgr.remove_api_key(service, index)
            config_mgr.add_api_key(service, new_api_key, tier=tier, priority=priority)

            print(f"\n[+] API key updated successfully for {service_name}!")
            display_keys_menu(config_mgr)
        else:
            print(f" FAILED: {test_result['message']}")
            print("[!] API key was not updated")

    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled")
    except (ValueError, IndexError):
        print("\n[!] Invalid input")


def extract_stream_to_quarantine(file_path, stream_name, stream_hash, quarantine_dir, metadata=None):
    """
    Extract an alternate data stream to quarantine directory

    Args:
        file_path: Path to file containing the stream
        stream_name: Name of the stream
        stream_hash: SHA256 hash of stream contents
        quarantine_dir: Directory to extract to
        metadata: Optional dict with additional metadata

    Returns:
        Tuple of (success, extracted_path, error_message)
    """
    try:
        # Create quarantine directory structure
        os.makedirs(quarantine_dir, exist_ok=True)

        # Create sanitized filename
        safe_filename = "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in os.path.basename(file_path))
        safe_streamname = "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in stream_name)

        # Use hash prefix for organization
        hash_prefix = stream_hash[:8]
        extract_subdir = os.path.join(quarantine_dir, hash_prefix)
        os.makedirs(extract_subdir, exist_ok=True)

        # Extracted file name: hash_filename_streamname.bin
        extracted_filename = f"{stream_hash}_{safe_filename}_{safe_streamname}.bin"
        extracted_path = os.path.join(extract_subdir, extracted_filename)

        # Read stream contents
        stream_path = f"{file_path}:{stream_name}"
        with open(stream_path, 'rb') as f:
            stream_data = f.read()

        # Write to quarantine
        with open(extracted_path, 'wb') as f:
            f.write(stream_data)

        # Create metadata sidecar file
        metadata_path = extracted_path + ".meta.txt"
        with open(metadata_path, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("ADS EXTRACTION METADATA\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Original File Path: {file_path}\n")
            f.write(f"Stream Name: {stream_name}\n")
            f.write(f"Stream Size: {len(stream_data)} bytes\n")
            f.write(f"SHA256 Hash: {stream_hash}\n")
            f.write(f"Extraction Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Extracted To: {extracted_path}\n")

            if metadata:
                f.write("\n" + "=" * 70 + "\n")
                f.write("THREAT INTELLIGENCE\n")
                f.write("=" * 70 + "\n\n")

                for key, value in metadata.items():
                    f.write(f"{key}: {value}\n")

        return (True, extracted_path, None)

    except PermissionError as e:
        return (False, None, f"Permission denied: {e}")
    except FileNotFoundError as e:
        return (False, None, f"File not found: {e}")
    except Exception as e:
        return (False, None, f"Extraction error: {e}")


def should_extract_stream(result, extract_filter):
    """
    Determine if a stream should be extracted based on filter criteria

    Args:
        result: Scan result dictionary
        extract_filter: Filter mode ('all', 'suspicious', 'high-risk', 'malicious')

    Returns:
        Boolean indicating whether to extract
    """
    if extract_filter == 'all':
        return True

    # Get combined risk assessment
    risk = result.get('Combined_Risk', 'UNKNOWN')

    # Get malicious indicators
    vt_malicious = result.get('VT_Malicious', 0)
    if isinstance(vt_malicious, str):
        try:
            vt_malicious = int(vt_malicious)
        except:
            vt_malicious = 0

    ha_score = result.get('HA_ThreatScore', 0)
    if isinstance(ha_score, str):
        try:
            ha_score = int(ha_score)
        except:
            ha_score = 0

    if extract_filter == 'malicious':
        # Extract if any service reports as malicious
        return vt_malicious > 0 or ha_score >= 70

    elif extract_filter == 'high-risk':
        # Extract high risk only
        return risk == 'HIGH'

    elif extract_filter == 'suspicious':
        # Extract medium or high risk
        return risk in ['MEDIUM', 'HIGH'] or vt_malicious > 0 or ha_score >= 40

    return False


def config_cli_mode(args, config_mgr):
    """Handle configuration CLI commands"""
    action = args.config.lower()

    if action == 'init':
        config_mgr.initialize()
        print(f"[+] Configuration initialized at: {config_mgr.config_file}")
        return True

    elif action == 'add':
        if not args.service or not args.key:
            print("[!] ERROR: --service and --key required for 'add' action")
            return False

        # Normalize service name (convert hyphen to underscore)
        service = args.service.replace('-', '_')
        tier = args.tier or 'free'

        print(f"[*] Testing {service} API key...", end='', flush=True)
        test_result = config_mgr.test_api_key(service, args.key)

        if not test_result['success']:
            print(f" FAILED: {test_result['message']}")
            return False

        print(f" SUCCESS! ({test_result['tier_info']})")

        config_mgr.add_api_key(service, args.key, tier=tier)
        print(f"[+] API key added for {service} ({tier} tier)")
        return True

    elif action == 'list':
        all_keys = config_mgr.list_api_keys()

        if not any(all_keys.values()):
            print("[*] No API keys configured")
            return True

        for service, keys in all_keys.items():
            if keys:
                print(f"\n{service.upper().replace('_', ' ')}:")
                for key_info in keys:
                    print(f"  [{key_info['index']}] {key_info['key']} "
                          f"(tier={key_info['tier']}, priority={key_info['priority']}, "
                          f"enabled={key_info['enabled']})")
        return True

    elif action == 'remove':
        if not args.service or args.index is None:
            print("[!] ERROR: --service and --index required for 'remove' action")
            return False

        # Normalize service name
        service = args.service.replace('-', '_')
        config_mgr.remove_api_key(service, args.index)
        print(f"[+] Removed {service} key at index {args.index}")
        return True

    elif action == 'test':
        if not args.service or not args.key:
            print("[!] ERROR: --service and --key required for 'test' action")
            return False

        # Normalize service name
        service = args.service.replace('-', '_')
        print(f"[*] Testing {service} API key...")
        test_result = config_mgr.test_api_key(service, args.key)

        if test_result['success']:
            print(f"[+] SUCCESS: {test_result['message']}")
            print(f"[+] Rate limits: {test_result['tier_info']}")
        else:
            print(f"[!] FAILED: {test_result['message']}")

        return test_result['success']

    else:
        print(f"[!] ERROR: Unknown config action: {action}")
        print("[!] Valid actions: init, add, list, remove, test")
        return False


def main():
    parser = argparse.ArgumentParser(
        description='NTFS ADS Scanner with Multi-Service Threat Intelligence (v2.1)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Interactive Management:
  %(prog)s --manage              Interactive menu for API key management
  %(prog)s --setup               First-time setup wizard

Configuration Management (CLI):
  %(prog)s --config init
  %(prog)s --config add --service virustotal --key YOUR_KEY --tier free
  %(prog)s --config add --service alienvault-otx --key YOUR_OTX_KEY
  %(prog)s --config list
  %(prog)s --config remove --service virustotal --index 0

Scanning Examples:
  %(prog)s C:\\Users --use-config
  %(prog)s C:\\Users --use-config --export-format json
  %(prog)s C:\\Users --api-key VT_KEY --skip-hybrid-analysis
  %(prog)s C:\\Users --resume previous_scan.csv --use-config
        """
    )

    # Path argument (optional if using config commands)
    parser.add_argument(
        'path',
        nargs='?',
        help='Path or drive to scan (e.g., C:\\Users, D:\\)'
    )

    # Configuration management
    parser.add_argument('--config', choices=['init', 'add', 'list', 'remove', 'test'],
                       help='Configuration management action')
    parser.add_argument('--service', choices=['virustotal', 'hybrid-analysis', 'alienvault-otx', 'metadefender'],
                       help='Service name for config actions')
    parser.add_argument('--key', help='API key for config actions')
    parser.add_argument('--tier', choices=['free', 'paid'], help='API tier for config add')
    parser.add_argument('--index', type=int, help='Key index for config remove')

    # Setup mode
    parser.add_argument('--setup', action='store_true',
                       help='Run interactive setup wizard')

    # Management mode
    parser.add_argument('--manage', action='store_true',
                       help='Run interactive API key management menu')

    # Scanning options
    parser.add_argument('--use-config', action='store_true',
                       help='Use API keys from configuration file')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-e', '--exclude-zone-identifier', action='store_true',
                       help='Exclude Zone.Identifier streams')
    parser.add_argument('--export-format', choices=['csv', 'json', 'html', 'stix'],
                       default='csv', help='Export format (default: csv)')

    # Legacy API key arguments (backward compatibility)
    parser.add_argument('-k', '--api-key', help='VirusTotal API key (legacy mode)')
    parser.add_argument('--skip-virustotal', action='store_true',
                       help='Skip VirusTotal lookups')
    parser.add_argument('--skip-hybrid-analysis', action='store_true',
                       help='Skip Hybrid Analysis lookups')

    # Advanced options
    parser.add_argument('-r', '--resume', help='Resume from previous scan CSV file')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://proxy:8080)')
    parser.add_argument('--no-cache', action='store_true', help='Disable results caching')
    parser.add_argument('--no-parallel', action='store_true',
                       help='Disable parallel API calls')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help='Logging level')

    # Extraction/Quarantine options
    parser.add_argument('--extract', '--quarantine', dest='quarantine_dir',
                       help='Extract ADS to quarantine directory for analysis')
    parser.add_argument('--extract-filter', choices=['all', 'suspicious', 'high-risk', 'malicious'],
                       default='all',
                       help='Filter which streams to extract (default: all)')

    args = parser.parse_args()

    # Initialize configuration manager
    config_mgr = ConfigManager()

    # Handle configuration CLI mode
    if args.config:
        if not config_mgr.config_exists():
            config_mgr.initialize()
        else:
            config_mgr.load_config()

        success = config_cli_mode(args, config_mgr)
        sys.exit(0 if success else 1)

    # Handle setup mode
    if args.setup:
        if not config_mgr.config_exists():
            config_mgr.initialize()
        else:
            config_mgr.load_config()

        interactive_setup(config_mgr)
        sys.exit(0)

    # Handle management mode
    if args.manage:
        if not config_mgr.config_exists():
            config_mgr.initialize()
        else:
            config_mgr.load_config()

        manage_keys_interactive(config_mgr)
        sys.exit(0)

    # Validate path argument for scanning
    if not args.path:
        print("[!] ERROR: Path argument required for scanning")
        print("[!] Use --help for usage information")
        sys.exit(1)

    if not os.path.exists(args.path):
        print(f"[!] ERROR: Path '{args.path}' does not exist or is not accessible")
        sys.exit(1)

    # Initialize configuration for scanning
    if not config_mgr.config_exists():
        print("[!] No configuration file found")

        if args.use_config:
            print("[!] Run with --setup to create configuration")
            sys.exit(1)
    else:
        config_mgr.load_config()

    # Setup logging
    logger = setup_logging(config_mgr.get_log_dir(), args.log_level)
    logger.info("=" * 70)
    logger.info("ADS Scanner v2.0 - Starting scan")
    logger.info("=" * 70)

    # Determine settings
    if args.use_config:
        exclude_zone_identifier = config_mgr.get_setting('exclude_zone_identifier', False)
        cache_enabled = not args.no_cache and config_mgr.get_setting('cache_enabled', True)
        cache_ttl_days = config_mgr.get_setting('cache_ttl_days', 7)
        proxy = args.proxy or config_mgr.get_setting('proxy')
        parallel_api_calls = not args.no_parallel and config_mgr.get_setting('parallel_api_calls', True)
    else:
        exclude_zone_identifier = args.exclude_zone_identifier
        cache_enabled = not args.no_cache
        cache_ttl_days = 7
        proxy = args.proxy
        parallel_api_calls = not args.no_parallel

    # Initialize cache manager
    cache_mgr = None
    if cache_enabled:
        cache_mgr = CacheManager(
            cache_dir=str(config_mgr.get_cache_dir()),
            ttl_days=cache_ttl_days,
            enabled=True
        )
        logger.info(f"Cache enabled: TTL={cache_ttl_days} days")

    # Initialize API key rotators
    vt_rotator = None
    ha_rotator = None
    otx_rotator = None
    metadefender_rotator = None

    if args.use_config:
        # Load from config file
        if not args.skip_virustotal:
            vt_keys = config_mgr.get_api_keys('virustotal')
            if vt_keys:
                vt_rotator = APIKeyRotator('virustotal', vt_keys, proxy=proxy)

        if not args.skip_hybrid_analysis:
            ha_keys = config_mgr.get_api_keys('hybrid_analysis')
            if ha_keys:
                ha_rotator = APIKeyRotator('hybrid_analysis', ha_keys, proxy=proxy)

        # New services
        otx_keys = config_mgr.get_api_keys('alienvault_otx')
        if otx_keys:
            otx_rotator = APIKeyRotator('alienvault_otx', otx_keys, proxy=proxy)

        metadefender_keys = config_mgr.get_api_keys('metadefender')
        if metadefender_keys:
            metadefender_rotator = APIKeyRotator('metadefender', metadefender_keys, proxy=proxy)
    else:
        # Legacy mode - single VT key from command line
        if args.api_key and not args.skip_virustotal:
            vt_keys = [{
                'key': args.api_key,
                'tier': 'free',
                'priority': 1,
                'requests_per_minute': 4,
                'requests_per_day': 500,
                'enabled': True
            }]
            vt_rotator = APIKeyRotator('virustotal', vt_keys, proxy=proxy)

    if not vt_rotator and not ha_rotator and not otx_rotator and not metadefender_rotator:
        print("[!] WARNING: No API keys configured")
        print("[!] Scanning will collect hashes but no threat intelligence lookups will be performed")
        print("[!] Run with --setup to configure API keys")

    # Set output file
    if args.output:
        output_file = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = args.export_format
        output_file = f"ADS_Report_{timestamp}.{ext}"

    # Load resume data
    resume_hashes = None
    if args.resume:
        resume_hashes = load_resume_data(args.resume)

    print(f"\n[*] Starting ADS scan...")
    print(f"[*] Path: {args.path}")
    print(f"[*] Output: {output_file} ({args.export_format.upper()})")
    print(f"[*] VirusTotal: {'Enabled' if vt_rotator else 'Disabled'}")
    print(f"[*] Hybrid Analysis: {'Enabled' if ha_rotator else 'Disabled'}")
    print(f"[*] AlienVault OTX: {'Enabled' if otx_rotator else 'Disabled'}")
    print(f"[*] MetaDefender: {'Enabled' if metadefender_rotator else 'Disabled'}")
    print(f"[*] Cache: {'Enabled' if cache_enabled else 'Disabled'}")
    print(f"[*] Parallel API calls: {'Enabled' if parallel_api_calls else 'Disabled'}")

    # Setup extraction/quarantine
    extraction_enabled = bool(args.quarantine_dir)
    extraction_manifest = []
    extraction_count = 0
    extraction_errors = 0

    if extraction_enabled:
        print(f"[*] Extraction: Enabled (filter: {args.extract_filter})")
        print(f"[*] Quarantine directory: {args.quarantine_dir}")
        os.makedirs(args.quarantine_dir, exist_ok=True)
    else:
        print(f"[*] Extraction: Disabled")

    # Scan and collect results
    results = []

    for result in scan_path(
        args.path,
        exclude_zone_identifier,
        vt_rotator,
        ha_rotator,
        otx_rotator,
        metadefender_rotator,
        cache_mgr,
        resume_hashes,
        logger,
        parallel_api_calls
    ):
        results.append(result)

        # Extract stream if enabled and matches filter
        if extraction_enabled and should_extract_stream(result, args.extract_filter):
            metadata = {
                'VT_DetectionRatio': result.get('VT_DetectionRatio', 'N/A'),
                'VT_Malicious': result.get('VT_Malicious', 'N/A'),
                'HA_ThreatScore': result.get('HA_ThreatScore', 'N/A'),
                'HA_Verdict': result.get('HA_Verdict', 'N/A'),
                'Combined_Risk': result.get('Combined_Risk', 'UNKNOWN'),
                'VT_Link': result.get('VT_Link', 'N/A'),
                'HA_ReportURL': result.get('HA_ReportURL', 'N/A')
            }

            success, extracted_path, error = extract_stream_to_quarantine(
                result['FilePath'],
                result['StreamName'],
                result['StreamSHA256'],
                args.quarantine_dir,
                metadata
            )

            if success:
                extraction_count += 1
                extraction_manifest.append({
                    'original_path': result['FilePath'],
                    'stream_name': result['StreamName'],
                    'extracted_path': extracted_path,
                    'hash': result['StreamSHA256'],
                    'risk': result.get('Combined_Risk', 'UNKNOWN')
                })
                logger.info(f"Extracted: {result['FileName']}:{result['StreamName']} -> {extracted_path}")
            else:
                extraction_errors += 1
                logger.error(f"Extraction failed: {result['FileName']}:{result['StreamName']} - {error}")

    # Export results
    scan_metadata = {
        'scan_date': datetime.now().isoformat(),
        'scan_path': args.path,
        'api_usage': {},
        'cache_stats': cache_mgr.get_stats() if cache_mgr else {}
    }

    if vt_rotator:
        scan_metadata['api_usage']['virustotal'] = vt_rotator.get_stats()
    if ha_rotator:
        scan_metadata['api_usage']['hybrid_analysis'] = ha_rotator.get_stats()
    if otx_rotator:
        scan_metadata['api_usage']['alienvault_otx'] = otx_rotator.get_stats()
    if metadefender_rotator:
        scan_metadata['api_usage']['metadefender'] = metadefender_rotator.get_stats()

    # Define CSV fieldnames
    fieldnames = [
        'FilePath', 'FileName', 'FileSize', 'FileExtension',
        'FileCreated', 'FileModified', 'FileAccessed',
        'StreamName', 'StreamSize', 'StreamType', 'StreamSHA256', 'StreamPreview',
        'VT_Found', 'VT_DetectionRatio', 'VT_Malicious', 'VT_Suspicious',
        'VT_Undetected', 'VT_Harmless', 'VT_DetectionEngines', 'VT_ScanDate', 'VT_Link',
        'HA_Found', 'HA_ThreatScore', 'HA_Verdict', 'HA_AVDetect',
        'HA_VXFamily', 'HA_JobID', 'HA_ReportURL', 'HA_ScanDate',
        'OTX_Found', 'OTX_PulseCount', 'OTX_MalwareFamilies', 'OTX_Reputation', 'OTX_Link',
        'MetaDefender_Found', 'MetaDefender_DetectionRatio', 'MetaDefender_Detected',
        'MetaDefender_TotalEngines', 'MetaDefender_ScanAllResult', 'MetaDefender_Link',
        'Combined_Risk', 'FlagForSubmission',
        'CachedResult', 'APIKeysUsed', 'ScanDate'
    ]

    # Export based on format
    if args.export_format == 'csv':
        export_to_csv(results, output_file, fieldnames)
    elif args.export_format == 'json':
        export_to_json(results, output_file, scan_metadata)
    elif args.export_format == 'html':
        export_to_html(results, output_file, scan_metadata)
    elif args.export_format == 'stix':
        export_to_stix(results, output_file, scan_metadata)

    # Print summary
    print("\n" + "=" * 70)
    print("Scan Complete!")
    print("=" * 70)
    print(f"ADS streams found:   {len(results)}")
    print(f"Report saved to:     {output_file}")

    if vt_rotator or ha_rotator:
        print("\nThreat Intelligence Summary:")

        if vt_rotator:
            vt_stats = vt_rotator.get_stats()
            print(f"  VirusTotal requests:   {vt_stats['total_requests']}")
            print(f"  VT keys used:          {vt_stats['total_keys']}")

        if ha_rotator:
            ha_stats = ha_rotator.get_stats()
            print(f"  Hybrid Analysis requests: {ha_stats['total_requests']}")
            print(f"  HA keys used:          {ha_stats['total_keys']}")

    if cache_mgr:
        cache_stats = cache_mgr.get_stats()
        print(f"\nCache Performance:")
        print(f"  Cache hits:    {cache_stats['cache_hits']}")
        print(f"  Cache misses:  {cache_stats['cache_misses']}")
        print(f"  Hit rate:      {cache_stats['hit_rate']}")

    # Show high risk findings
    high_risk = [r for r in results if r.get('Combined_Risk') == 'HIGH']
    if high_risk:
        print(f"\n[!!!] {len(high_risk)} HIGH RISK stream(s) detected:")
        for r in high_risk[:10]:
            print(f"    - {r['FileName']}:{r['StreamName']}")
            if r['VT_Link'] != 'N/A':
                print(f"      VT: {r['VT_Link']}")
            if r.get('HA_ReportURL') and r['HA_ReportURL'] != 'N/A':
                print(f"      HA: {r['HA_ReportURL']}")

    # Save extraction manifest if any streams were extracted
    if extraction_enabled and extraction_count > 0:
        manifest_path = os.path.join(args.quarantine_dir, 'extraction_manifest.json')
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump({
                'extraction_date': datetime.now().isoformat(),
                'scan_path': args.path,
                'extraction_filter': args.extract_filter,
                'total_extracted': extraction_count,
                'extraction_errors': extraction_errors,
                'extractions': extraction_manifest
            }, f, indent=2)
        print(f"\nExtraction manifest saved to: {manifest_path}")

    # Print extraction summary if enabled
    if extraction_enabled:
        print(f"\nExtraction Summary:")
        print(f"  Streams extracted:  {extraction_count}")
        print(f"  Extraction errors:  {extraction_errors}")
        print(f"  Quarantine dir:     {args.quarantine_dir}")

    print("=" * 70)
    logger.info("Scan completed successfully")


if __name__ == '__main__':
    main()
