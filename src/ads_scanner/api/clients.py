"""
API Clients for Threat Intelligence Services
Supports VirusTotal, Hybrid Analysis, AlienVault OTX, and MetaDefender FileScan.io with rate limiting
"""

import time
import json
from urllib import request, error
from typing import Dict, Optional, List
from datetime import datetime


class VirusTotalAPI:
    """VirusTotal API v3 client with rate limiting"""

    def __init__(self, api_key: str, proxy: Optional[str] = None):
        """
        Initialize VirusTotal API client

        Args:
            api_key: VirusTotal API key
            proxy: Proxy URL (e.g., http://proxy:8080)
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.proxy = proxy

        # Default rate limits (free tier)
        self.requests_per_minute = 4
        self.requests_per_day = 500

        # Rate limiting tracking
        self.request_times: List[float] = []
        self.daily_count = 0
        self.last_request_time = 0.0

    def set_rate_limits(self, requests_per_minute: int, requests_per_day: int):
        """Set custom rate limits for this API key"""
        self.requests_per_minute = requests_per_minute
        self.requests_per_day = requests_per_day

    def _wait_for_rate_limit(self) -> bool:
        """
        Wait if necessary to respect rate limits

        Returns:
            True if can proceed, False if daily limit reached
        """
        now = time.time()

        # Check daily limit
        if self.daily_count >= self.requests_per_day:
            return False

        # Clean old request times (older than 1 minute)
        self.request_times = [t for t in self.request_times if now - t < 60]

        # Check per-minute limit
        if len(self.request_times) >= self.requests_per_minute:
            sleep_time = 60 - (now - self.request_times[0])
            if sleep_time > 0:
                print(f"[*] VT rate limit: Waiting {int(sleep_time) + 1} seconds...", end='', flush=True)
                time.sleep(sleep_time + 1)
                print(" Done")
                self.request_times = []

        return True

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a file hash in VirusTotal

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Dictionary with VT results or None if lookup fails
        """
        if not self._wait_for_rate_limit():
            return None

        url = f"{self.base_url}/files/{file_hash}"

        try:
            req = request.Request(url)
            req.add_header('x-apikey', self.api_key)

            # Configure proxy if provided
            if self.proxy:
                req.set_proxy(self.proxy, 'http')
                req.set_proxy(self.proxy, 'https')

            self.request_times.append(time.time())
            self.daily_count += 1

            with request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

                attrs = data['data']['attributes']
                stats = attrs['last_analysis_stats']

                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                undetected = stats.get('undetected', 0)
                harmless = stats.get('harmless', 0)
                total = malicious + suspicious + undetected + harmless

                # Get list of engines that detected as malicious
                detection_engines = []
                for engine, result in attrs.get('last_analysis_results', {}).items():
                    if result.get('category') == 'malicious':
                        detection_engines.append(f"{engine}:{result.get('result', 'unknown')}")

                return {
                    'found': True,
                    'malicious': malicious,
                    'suspicious': suspicious,
                    'undetected': undetected,
                    'harmless': harmless,
                    'total': total,
                    'detection_ratio': f"{malicious}/{total}",
                    'detection_engines': '; '.join(detection_engines[:10]),
                    'scan_date': attrs.get('last_analysis_date', ''),
                    'link': f"https://www.virustotal.com/gui/file/{file_hash}"
                }

        except error.HTTPError as e:
            if e.code == 404:
                # File not found in VT database
                return {
                    'found': False,
                    'malicious': 0,
                    'suspicious': 0,
                    'undetected': 0,
                    'harmless': 0,
                    'total': 0,
                    'detection_ratio': 'Not in VT DB',
                    'detection_engines': '',
                    'scan_date': '',
                    'link': f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            elif e.code == 429:
                print("\n[!] VT rate limit exceeded (429). Waiting 60 seconds...")
                time.sleep(60)
                return self.lookup_hash(file_hash)
            elif e.code == 401:
                print(f"\n[!] VT authentication error (401) - invalid API key")
                return None
            else:
                print(f"\n[!] VT HTTP Error {e.code} for hash {file_hash}")
                return None
        except Exception as e:
            print(f"\n[!] VT error looking up hash {file_hash}: {e}")
            return None

    def is_rate_limited(self) -> bool:
        """Check if currently rate limited"""
        return self.daily_count >= self.requests_per_day

    def get_remaining_quota(self) -> int:
        """Get remaining daily quota"""
        return max(0, self.requests_per_day - self.daily_count)


class HybridAnalysisAPI:
    """Hybrid Analysis API v2 client with rate limiting"""

    def __init__(self, api_key: str, proxy: Optional[str] = None):
        """
        Initialize Hybrid Analysis API client

        Args:
            api_key: Hybrid Analysis API key
            proxy: Proxy URL (e.g., http://proxy:8080)
        """
        self.api_key = api_key
        self.base_url = "https://www.hybrid-analysis.com/api/v2"
        self.proxy = proxy

        # Rate limits (free tier)
        self.requests_per_minute = 5
        self.requests_per_hour = 200

        # Rate limiting tracking
        self.request_times: List[float] = []
        self.hourly_count = 0
        self.last_hour_reset = time.time()

    def set_rate_limits(self, requests_per_minute: int, requests_per_hour: int):
        """Set custom rate limits for this API key"""
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour

    def _wait_for_rate_limit(self) -> bool:
        """
        Wait if necessary to respect rate limits

        Returns:
            True if can proceed, False if hourly limit reached
        """
        now = time.time()

        # Reset hourly counter if needed
        if now - self.last_hour_reset >= 3600:
            self.hourly_count = 0
            self.last_hour_reset = now

        # Check hourly limit
        if self.hourly_count >= self.requests_per_hour:
            return False

        # Clean old request times (older than 1 minute)
        self.request_times = [t for t in self.request_times if now - t < 60]

        # Check per-minute limit
        if len(self.request_times) >= self.requests_per_minute:
            sleep_time = 60 - (now - self.request_times[0])
            if sleep_time > 0:
                print(f"[*] HA rate limit: Waiting {int(sleep_time) + 1} seconds...", end='', flush=True)
                time.sleep(sleep_time + 1)
                print(" Done")
                self.request_times = []

        return True

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a file hash in Hybrid Analysis

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Dictionary with HA results or None if lookup fails
        """
        if not self._wait_for_rate_limit():
            return None

        url = f"{self.base_url}/search/hash"

        try:
            req = request.Request(f"{url}?hash={file_hash}")
            req.add_header('api-key', self.api_key)
            req.add_header('User-Agent', 'Falcon Sandbox')
            req.add_header('accept', 'application/json')

            # Configure proxy if provided
            if self.proxy:
                req.set_proxy(self.proxy, 'http')
                req.set_proxy(self.proxy, 'https')

            self.request_times.append(time.time())
            self.hourly_count += 1

            with request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

                # HA returns a list of results, take the first one if available
                if not data or len(data) == 0:
                    return {
                        'found': False,
                        'threat_score': 0,
                        'verdict': 'no-verdict',
                        'av_detect': 0,
                        'vx_family': '',
                        'job_id': '',
                        'report_url': ''
                    }

                # Use the first result (most recent analysis)
                result = data[0]

                threat_score = result.get('threat_score', 0)
                verdict = result.get('verdict', 'no-verdict')
                av_detect = result.get('av_detect', 0)
                vx_family = result.get('vx_family', '')
                job_id = result.get('job_id', '')

                # Build report URL
                report_url = ""
                if job_id:
                    report_url = f"https://www.hybrid-analysis.com/sample/{job_id}"

                return {
                    'found': True,
                    'threat_score': threat_score,
                    'verdict': verdict,
                    'av_detect': av_detect,
                    'vx_family': vx_family,
                    'job_id': job_id,
                    'report_url': report_url,
                    'scan_date': result.get('analysis_start_time', '')
                }

        except error.HTTPError as e:
            if e.code == 404:
                # File not found in HA database
                return {
                    'found': False,
                    'threat_score': 0,
                    'verdict': 'no-verdict',
                    'av_detect': 0,
                    'vx_family': '',
                    'job_id': '',
                    'report_url': ''
                }
            elif e.code == 429:
                print(f"\n[!] HA rate limit exceeded (429). Waiting 60 seconds...")
                time.sleep(60)
                return self.lookup_hash(file_hash)
            elif e.code == 401:
                print(f"\n[!] HA authentication error (401) - invalid API key")
                return None
            else:
                print(f"\n[!] HA HTTP Error {e.code} for hash {file_hash}")
                return None
        except Exception as e:
            print(f"\n[!] HA error looking up hash {file_hash}: {e}")
            return None


class AlienVaultOTXAPI:
    """AlienVault OTX API client with rate limiting"""

    def __init__(self, api_key: str, proxy: Optional[str] = None):
        """
        Initialize AlienVault OTX API client

        Args:
            api_key: AlienVault OTX API key
            proxy: Proxy URL (e.g., http://proxy:8080)
        """
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.proxy = proxy

        # Rate limits (free tier)
        self.requests_per_day = 1000
        self.daily_count = 0
        self.last_day_reset = self._get_midnight_timestamp()

    def _get_midnight_timestamp(self) -> float:
        """Get timestamp for midnight today"""
        now = datetime.now()
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return midnight.timestamp()

    def _wait_for_rate_limit(self) -> bool:
        """Wait if necessary to respect daily rate limits"""
        now = time.time()

        # Reset daily counter if new day
        if now >= self.last_day_reset + 86400:
            self.daily_count = 0
            self.last_day_reset = self._get_midnight_timestamp()

        # Check daily limit
        if self.daily_count >= self.requests_per_day:
            print(f"[!] OTX daily limit reached ({self.requests_per_day}/day)")
            return False

        return True

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a file hash in AlienVault OTX

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Dictionary with OTX results or None if lookup fails
        """
        if not self._wait_for_rate_limit():
            return None

        url = f"{self.base_url}/indicators/file/{file_hash}"

        try:
            req = request.Request(url)
            req.add_header('X-OTX-API-KEY', self.api_key)

            # Configure proxy if provided
            if self.proxy:
                req.set_proxy(self.proxy, 'http')
                req.set_proxy(self.proxy, 'https')

            self.daily_count += 1

            with request.urlopen(req, timeout=30) as response:
                response_data = response.read().decode('utf-8')
                try:
                    data = json.loads(response_data)
                except json.JSONDecodeError as e:
                    print(f"[!] OTX JSON decode error: {e}")
                    print(f"[!] Response: {response_data[:200]}...")
                    return None

                # Extract relevant information
                pulses = data.get('pulse_info', {}).get('pulses', [])
                malware_families = []
                for pulse in pulses:
                    if 'malware_families' in pulse:
                        families = pulse['malware_families']
                        for family in families:
                            # Handle both string and dict formats
                            if isinstance(family, dict):
                                # Extract name from dict if available
                                family_name = family.get('display_name') or family.get('name') or family.get('value') or str(family)
                                malware_families.append(family_name)
                            elif isinstance(family, str):
                                malware_families.append(family)

                # Remove duplicates while preserving order
                seen = set()
                unique_families = []
                for family in malware_families:
                    if family not in seen:
                        seen.add(family)
                        unique_families.append(family)

                return {
                    'found': len(pulses) > 0,
                    'pulse_count': len(pulses),
                    'malware_families': unique_families,
                    'reputation': data.get('reputation', 0),
                    'otx_link': f"https://otx.alienvault.com/indicator/file/{file_hash}"
                }

        except error.HTTPError as e:
            if e.code == 404:
                return {
                    'found': False,
                    'pulse_count': 0,
                    'malware_families': [],
                    'reputation': 0,
                    'otx_link': f"https://otx.alienvault.com/indicator/file/{file_hash}"
                }
            elif e.code == 429:
                print(f"[!] OTX rate limit exceeded. Waiting until tomorrow...")
                return None
            elif e.code == 401:
                print(f"[!] OTX authentication error (401) - invalid API key")
                return None
            else:
                print(f"[!] OTX HTTP Error {e.code} for hash {file_hash}")
                return None
        except Exception as e:
            print(f"[!] OTX lookup error: {e}")
            return None


class MetaDefenderAPI:
    """MetaDefender FileScan.io API client with rate limiting"""

    def __init__(self, api_key: str, proxy: Optional[str] = None):
        """
        Initialize MetaDefender API client

        Args:
            api_key: MetaDefender API key
            proxy: Proxy URL (e.g., http://proxy:8080)
        """
        self.api_key = api_key
        self.base_url = "https://api.metadefender.com/v4"
        self.proxy = proxy

        # Rate limits (free tier - conservative estimate)
        self.requests_per_minute = 10
        self.request_times: List[float] = []

    def _wait_for_rate_limit(self) -> bool:
        """Wait if necessary to respect rate limits"""
        now = time.time()

        # Clean old request times (older than 1 minute)
        self.request_times = [t for t in self.request_times if now - t < 60]

        # Check per-minute limit
        if len(self.request_times) >= self.requests_per_minute:
            sleep_time = 60 - (now - self.request_times[0])
            if sleep_time > 0:
                print(f"[*] MetaDefender rate limit: Waiting {int(sleep_time) + 1} seconds...", end='', flush=True)
                time.sleep(sleep_time + 1)
                print(" Done")
                self.request_times = []

        return True

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a file hash in MetaDefender

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Dictionary with MetaDefender results or None if lookup fails
        """
        if not self._wait_for_rate_limit():
            return None

        url = f"{self.base_url}/hash/{file_hash}"

        try:
            req = request.Request(url)
            req.add_header('apikey', self.api_key)

            # Configure proxy if provided
            if self.proxy:
                req.set_proxy(self.proxy, 'http')
                req.set_proxy(self.proxy, 'https')

            self.request_times.append(time.time())

            with request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

                # Extract scan results
                scan_results = data.get('scan_results', {})
                scan_all_result = scan_results.get('scan_all_result_a', '')

                # Count detections
                detected = sum(1 for result in scan_results.values()
                              if isinstance(result, str) and result.lower() != 'clean')

                total_engines = len(scan_results) - 1  # Exclude scan_all_result_a

                return {
                    'found': detected > 0,
                    'detected': detected,
                    'total_engines': total_engines,
                    'detection_ratio': f"{detected}/{total_engines}" if total_engines > 0 else "0/0",
                    'scan_all_result': scan_all_result,
                    'metadefender_link': f"https://metadefender.opswat.com/#/file/{data.get('data_id', file_hash)}"
                }

        except error.HTTPError as e:
            if e.code == 404:
                return {
                    'found': False,
                    'detected': 0,
                    'total_engines': 0,
                    'detection_ratio': 'Not in MetaDefender DB',
                    'scan_all_result': 'Not found',
                    'metadefender_link': f"https://metadefender.opswat.com/#/file/{file_hash}"
                }
            elif e.code == 429:
                print(f"[!] MetaDefender rate limit exceeded. Waiting 60 seconds...")
                time.sleep(60)
                return self.lookup_hash(file_hash)
            elif e.code == 401:
                print(f"[!] MetaDefender authentication error (401) - invalid API key")
                return None
            else:
                print(f"[!] MetaDefender HTTP Error {e.code} for hash {file_hash}")
                return None
        except Exception as e:
            print(f"[!] MetaDefender lookup error: {e}")
            return None


class AnyRunAPI:
    """Any.Run API client with rate limiting"""

    def __init__(self, api_key: str, proxy: Optional[str] = None):
        """
        Initialize Any.Run API client

        Args:
            api_key: Any.Run API key
            proxy: Proxy URL (e.g., http://proxy:8080)
        """
        self.api_key = api_key
        self.base_url = "https://api.any.run/v1"
        self.proxy = proxy

        # Default rate limits (based on typical free tier)
        self.requests_per_minute = 10

        # Rate limiting tracking
        self.request_times = []

    def set_rate_limits(self, requests_per_minute: int):
        """Set custom rate limits for this API key"""
        self.requests_per_minute = requests_per_minute

    def _wait_for_rate_limit(self) -> bool:
        """
        Wait if necessary to respect rate limits

        Returns:
            True if can proceed
        """
        now = time.time()

        # Clean old request times (older than 1 minute)
        self.request_times = [t for t in self.request_times if now - t < 60]

        # Check per-minute limit
        if len(self.request_times) >= self.requests_per_minute:
            sleep_time = 60 - (now - self.request_times[0])
            if sleep_time > 0:
                print(f"[*] Any.Run rate limit: Waiting {int(sleep_time) + 1} seconds...", end='', flush=True)
                time.sleep(sleep_time + 1)
                print(" Done")
                self.request_times = []

        return True

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a file hash in Any.Run

        Args:
            file_hash: SHA256 hash of the file

        Returns:
            Dictionary with Any.Run results or None if lookup fails
        """
        if not self._wait_for_rate_limit():
            return None

        url = f"{self.base_url}/sample/{file_hash}"

        try:
            req = request.Request(url)
            req.add_header('Authorization', f'Bearer {self.api_key}')
            req.add_header('Accept', 'application/json')

            # Configure proxy if provided
            if self.proxy:
                req.set_proxy(self.proxy, 'http')
                req.set_proxy(self.proxy, 'https')

            self.request_times.append(time.time())

            with request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

                # Parse Any.Run results
                # Note: This is a simplified implementation - actual Any.Run API may differ
                sample_info = data.get('data', {}).get('sample', {})
                verdict = sample_info.get('verdict', 'unknown')
                score = sample_info.get('score', 0)

                # Determine if malicious based on score (Any.Run typically uses 0-100 scale)
                is_malicious = score > 50  # Threshold may vary

                return {
                    'found': True,
                    'malicious': is_malicious,
                    'verdict': verdict,
                    'score': score,
                    'detection_ratio': f"{int(score)}%",
                    'scan_date': sample_info.get('date', ''),
                    'link': f"https://app.any.run/submission/{file_hash}"
                }

        except error.HTTPError as e:
            if e.code == 404:
                # File not found in Any.Run database
                return {
                    'found': False,
                    'malicious': False,
                    'verdict': 'not_found',
                    'score': 0,
                    'detection_ratio': 'Not in Any.Run DB',
                    'scan_date': '',
                    'link': f"https://app.any.run/submission/{file_hash}"
                }
            elif e.code == 429:
                print(f"[!] Any.Run rate limit exceeded. Waiting 60 seconds...")
                time.sleep(60)
                return self.lookup_hash(file_hash)
            elif e.code == 401:
                print(f"[!] Any.Run authentication error (401) - invalid API key")
                return None
            else:
                print(f"[!] Any.Run HTTP Error {e.code} for hash {file_hash}")
                return None
        except Exception as e:
            print(f"[!] Any.Run lookup error: {e}")
            return None

    def is_rate_limited(self) -> bool:
        """Check if currently rate limited"""
        now = time.time()
        self.request_times = [t for t in self.request_times if now - t < 60]
        return len(self.request_times) >= self.requests_per_minute

    def get_remaining_quota(self) -> int:
        """Get remaining quota for the current minute"""
        now = time.time()
        self.request_times = [t for t in self.request_times if now - t < 60]
        return max(0, self.requests_per_minute - len(self.request_times))