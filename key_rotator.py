"""
API Key Rotation Manager
Manages multiple API keys per service with automatic rotation on rate limits
"""

import time
from typing import List, Dict, Optional, Any
from api_clients import VirusTotalAPI, HybridAnalysisAPI, AlienVaultOTXAPI, MetaDefenderAPI


class APIKeyRotator:
    """Manages multiple API keys for a service with automatic rotation"""

    def __init__(self, service_name: str, keys_config: List[Dict[str, Any]], proxy: Optional[str] = None):
        """
        Initialize API key rotator

        Args:
            service_name: Service name (virustotal, hybrid_analysis)
            keys_config: List of key configurations with decrypted keys
            proxy: Proxy URL (optional)
        """
        self.service_name = service_name.lower()
        self.keys: List[Dict[str, Any]] = []
        self.proxy = proxy
        self.current_index = 0

        # Initialize keys
        for idx, key_cfg in enumerate(keys_config):
            if not key_cfg.get('enabled', True):
                continue

            key_info = {
                'index': idx,
                'api_key': key_cfg['key'],
                'tier': key_cfg.get('tier', 'free'),
                'priority': key_cfg.get('priority', 99),
                'rpm': key_cfg.get('requests_per_minute'),
                'rpd': key_cfg.get('requests_per_day'),
                'rph': key_cfg.get('requests_per_hour'),
                'rate_limited_until': None,
                'api_client': None
            }

            # Create API client instance
            if self.service_name == 'virustotal':
                client = VirusTotalAPI(key_cfg['key'], proxy=proxy)
                if key_info['rpm'] and key_info['rpd']:
                    client.set_rate_limits(key_info['rpm'], key_info['rpd'])
                key_info['api_client'] = client

            elif self.service_name == 'hybrid_analysis':
                client = HybridAnalysisAPI(key_cfg['key'], proxy=proxy)
                if key_info['rpm'] and key_info['rph']:
                    client.set_rate_limits(key_info['rpm'], key_info['rph'])
                key_info['api_client'] = client

            elif self.service_name == 'alienvault_otx':
                client = AlienVaultOTXAPI(key_cfg['key'], proxy=proxy)
                key_info['api_client'] = client

            elif self.service_name == 'metadefender':
                client = MetaDefenderAPI(key_cfg['key'], proxy=proxy)
                key_info['api_client'] = client

            self.keys.append(key_info)

        # Sort by priority (1 = highest)
        self.keys.sort(key=lambda x: x['priority'])

        print(f"[+] Initialized {len(self.keys)} API key(s) for {self.service_name}")

    def get_next_available_client(self) -> Optional[Any]:
        """
        Get next available API client (not rate limited)

        Returns:
            API client instance or None if all keys are rate limited
        """
        if not self.keys:
            return None

        # Check all keys starting from current index
        for attempt in range(len(self.keys)):
            idx = (self.current_index + attempt) % len(self.keys)
            key_info = self.keys[idx]

            # Check if rate limited
            if key_info['rate_limited_until'] is not None:
                if time.time() < key_info['rate_limited_until']:
                    continue  # Still rate limited
                else:
                    key_info['rate_limited_until'] = None  # Expired

            # Check if client is rate limited
            client = key_info['api_client']
            if client:
                # OTX and MetaDefender don't have is_rate_limited method, so assume available
                if self.service_name in ['alienvault_otx', 'metadefender']:
                    self.current_index = (idx + 1) % len(self.keys)
                    return client
                elif not client.is_rate_limited():
                    self.current_index = (idx + 1) % len(self.keys)
                    return client

        # All keys are rate limited
        return None

    def mark_rate_limited(self, api_client: Any, duration_seconds: int = 60):
        """
        Mark an API key as rate limited

        Args:
            api_client: The API client instance
            duration_seconds: Duration of rate limit in seconds
        """
        for key_info in self.keys:
            if key_info['api_client'] is api_client:
                key_info['rate_limited_until'] = time.time() + duration_seconds
                tier = key_info['tier']
                print(f"[!] {self.service_name} key ({tier}) rate limited for {duration_seconds}s")
                break

    def has_available_keys(self) -> bool:
        """Check if any keys are available (not rate limited)"""
        return self.get_next_available_client() is not None

    def get_total_keys(self) -> int:
        """Get total number of keys"""
        return len(self.keys)

    def get_active_keys(self) -> int:
        """Get number of active (not rate limited) keys"""
        active = 0
        for key_info in self.keys:
            if key_info['rate_limited_until'] is None or time.time() >= key_info['rate_limited_until']:
                if key_info['api_client'] and not key_info['api_client'].is_rate_limited():
                    active += 1
        return active

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about key usage"""
        total_requests = 0
        remaining_quota = 0

        for key_info in self.keys:
            client = key_info['api_client']
            if client:
                if self.service_name == 'virustotal':
                    total_requests += client.daily_count
                    remaining_quota += client.get_remaining_quota()
                elif self.service_name == 'hybrid_analysis':
                    total_requests += client.hourly_count
                    remaining_quota += client.get_remaining_quota()
                elif self.service_name == 'alienvault_otx':
                    total_requests += client.daily_count
                    remaining_quota += max(0, 1000 - client.daily_count)  # OTX free tier limit
                elif self.service_name == 'metadefender':
                    # MetaDefender doesn't track total requests, so we can't provide accurate stats
                    total_requests += len(client.request_times)
                    remaining_quota = "Unknown"  # No quota info available

        return {
            'service': self.service_name,
            'total_keys': len(self.keys),
            'active_keys': self.get_active_keys(),
            'total_requests': total_requests,
            'remaining_quota': remaining_quota
        }

    def lookup_hash(self, file_hash: str) -> Optional[Dict]:
        """
        Look up a hash using the next available API key

        Args:
            file_hash: SHA256 hash to look up

        Returns:
            API result dictionary or None if no keys available
        """
        client = self.get_next_available_client()
        if client is None:
            print(f"[!] No available {self.service_name} API keys")
            return None

        result = client.lookup_hash(file_hash)

        # If client is now rate limited, mark it
        if client.is_rate_limited():
            self.mark_rate_limited(client)

        return result

    def __repr__(self) -> str:
        stats = self.get_stats()
        return (
            f"<APIKeyRotator service={stats['service']} "
            f"total_keys={stats['total_keys']} "
            f"active_keys={stats['active_keys']} "
            f"requests={stats['total_requests']} "
            f"quota={stats['remaining_quota']}>"
        )
