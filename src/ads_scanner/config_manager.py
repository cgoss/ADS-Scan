"""
Configuration Manager for ADS Scanner
Handles configuration file I/O, DPAPI encryption, and API key management
"""

import os
import json
import base64
import ctypes
from ctypes import wintypes
from typing import Dict, List, Optional, Any
from pathlib import Path


class DPAPIManager:
    """Handles Windows DPAPI encryption/decryption for API keys"""

    def __init__(self):
        """Initialize DPAPI with Windows Crypto API"""
        try:
            self.crypt32 = ctypes.windll.crypt32
            self._setup_structures()
        except (AttributeError, OSError) as e:
            raise RuntimeError("DPAPI requires Windows OS") from e

    def _setup_structures(self):
        """Setup ctypes structures for DPAPI"""
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ('cbData', wintypes.DWORD),
                ('pbData', ctypes.POINTER(ctypes.c_char))
            ]

        self.DATA_BLOB = DATA_BLOB

        # CryptProtectData
        self.crypt32.CryptProtectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),  # pDataIn
            wintypes.LPCWSTR,           # szDataDescr
            ctypes.POINTER(DATA_BLOB),  # pOptionalEntropy
            ctypes.c_void_p,            # pvReserved
            ctypes.c_void_p,            # pPromptStruct
            wintypes.DWORD,             # dwFlags
            ctypes.POINTER(DATA_BLOB)   # pDataOut
        ]
        self.crypt32.CryptProtectData.restype = wintypes.BOOL

        # CryptUnprotectData
        self.crypt32.CryptUnprotectData.argtypes = [
            ctypes.POINTER(DATA_BLOB),  # pDataIn
            ctypes.POINTER(wintypes.LPWSTR),  # ppszDataDescr
            ctypes.POINTER(DATA_BLOB),  # pOptionalEntropy
            ctypes.c_void_p,            # pvReserved
            ctypes.c_void_p,            # pPromptStruct
            wintypes.DWORD,             # dwFlags
            ctypes.POINTER(DATA_BLOB)   # pDataOut
        ]
        self.crypt32.CryptUnprotectData.restype = wintypes.BOOL

        # LocalFree
        self.kernel32 = ctypes.windll.kernel32
        self.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel32.LocalFree.restype = wintypes.HANDLE

    def encrypt_string(self, plaintext: str) -> str:
        """
        Encrypt a string using Windows DPAPI

        Args:
            plaintext: String to encrypt

        Returns:
            Base64-encoded encrypted string
        """
        if not plaintext:
            return ""

        # Convert string to bytes
        plaintext_bytes = plaintext.encode('utf-8')

        # Create input blob
        data_in = self.DATA_BLOB()
        data_in.pbData = ctypes.cast(
            ctypes.create_string_buffer(plaintext_bytes, len(plaintext_bytes)),
            ctypes.POINTER(ctypes.c_char)
        )
        data_in.cbData = len(plaintext_bytes)

        # Create output blob
        data_out = self.DATA_BLOB()

        # Encrypt
        if not self.crypt32.CryptProtectData(
            ctypes.byref(data_in),
            "ADS Scanner API Key",
            None,
            None,
            None,
            0,
            ctypes.byref(data_out)
        ):
            raise RuntimeError("Failed to encrypt data with DPAPI")

        # Copy encrypted data
        encrypted_bytes = ctypes.string_at(data_out.pbData, data_out.cbData)

        # Free memory
        self.kernel32.LocalFree(data_out.pbData)

        # Return base64-encoded string
        return base64.b64encode(encrypted_bytes).decode('ascii')

    def decrypt_string(self, encrypted: str) -> str:
        """
        Decrypt a DPAPI-encrypted string

        Args:
            encrypted: Base64-encoded encrypted string

        Returns:
            Decrypted plaintext string
        """
        if not encrypted:
            return ""

        # Decode base64
        encrypted_bytes = base64.b64decode(encrypted)

        # Create input blob
        data_in = self.DATA_BLOB()
        data_in.pbData = ctypes.cast(
            ctypes.create_string_buffer(encrypted_bytes, len(encrypted_bytes)),
            ctypes.POINTER(ctypes.c_char)
        )
        data_in.cbData = len(encrypted_bytes)

        # Create output blob
        data_out = self.DATA_BLOB()

        # Decrypt
        if not self.crypt32.CryptUnprotectData(
            ctypes.byref(data_in),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(data_out)
        ):
            raise RuntimeError("Failed to decrypt data with DPAPI. Data may be encrypted by another user.")

        # Copy decrypted data
        decrypted_bytes = ctypes.string_at(data_out.pbData, data_out.cbData)

        # Free memory
        self.kernel32.LocalFree(data_out.pbData)

        # Return decoded string
        return decrypted_bytes.decode('utf-8')


class ConfigManager:
    """Manages ADS Scanner configuration file"""

    CONFIG_VERSION = "1.0"

    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize configuration manager

        Args:
            config_dir: Configuration directory path (default: %LOCALAPPDATA%\ADSScanner)
        """
        if config_dir is None:
            localappdata = os.environ.get('LOCALAPPDATA', os.path.expanduser('~'))
            config_dir = os.path.join(localappdata, 'ADSScanner')

        self.config_dir = Path(config_dir)
        self.config_file = self.config_dir / 'config.json'
        self.cache_dir = self.config_dir / 'cache'
        self.log_dir = self.config_dir / 'logs'

        self.dpapi = DPAPIManager()
        self.config = None

    def initialize(self):
        """Initialize configuration directory structure"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        if not self.config_file.exists():
            self._create_default_config()

    def _create_default_config(self):
        """Create default configuration file"""
        default_config = {
            "version": self.CONFIG_VERSION,
            "api_keys": {
                "virustotal": [],
                "hybrid_analysis": [],
                "alienvault_otx": [],
                "metadefender": [],
                "any_run": []
            },
            "settings": {
                "exclude_zone_identifier": False,
                "default_output_path": None,
                "parallel_api_calls": True,
                "cache_enabled": True,
                "cache_ttl_days": 7,
                "proxy": None,
                "log_level": "INFO",
                "export_format": "csv"
            }
        }

        self._save_config(default_config)
        self.config = default_config

    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file

        Returns:
            Configuration dictionary
        """
        if not self.config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")

        with open(self.config_file, 'r', encoding='utf-8-sig') as f:
            self.config = json.load(f)

        return self.config

    def _save_config(self, config: Dict[str, Any]):
        """Save configuration to file"""
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        self.config = config

    def save_config(self):
        """Save current configuration to file"""
        if self.config is None:
            raise ValueError("No configuration loaded")
        self._save_config(self.config)

    def add_api_key(
        self,
        service: str,
        api_key: str,
        tier: str = "free",
        requests_per_minute: Optional[int] = None,
        requests_per_day: Optional[int] = None,
        requests_per_hour: Optional[int] = None,
        priority: int = 99,
        enabled: bool = True
    ) -> bool:
        """
        Add an API key for a service

        Args:
            service: Service name (virustotal, hybrid_analysis)
            api_key: Plaintext API key
            tier: API tier (free, paid)
            requests_per_minute: Rate limit per minute
            requests_per_day: Rate limit per day
            requests_per_hour: Rate limit per hour
            priority: Key priority (1=highest)
            enabled: Whether key is enabled

        Returns:
            True if successful
        """
        if self.config is None:
            self.load_config()

        service = service.lower()
        if service not in self.config['api_keys']:
            raise ValueError(f"Unknown service: {service}")

        # Set default rate limits based on service and tier
        if service == "virustotal":
            if tier == "free":
                requests_per_minute = requests_per_minute or 4
                requests_per_day = requests_per_day or 500
            else:  # paid
                requests_per_minute = requests_per_minute or 1000
                requests_per_day = requests_per_day or 300000
        elif service == "hybrid_analysis":
            requests_per_minute = requests_per_minute or 5
            requests_per_hour = requests_per_hour or 200
        elif service == "alienvault_otx":
            # OTX uses daily limits only
            requests_per_day = requests_per_day or 1000
        elif service == "metadefender":
            # MetaDefender uses per-minute limits
            requests_per_minute = requests_per_minute or 10
        elif service == "any_run":
            # Any.Run uses per-minute limits
            requests_per_minute = requests_per_minute or 10

        # Encrypt API key
        encrypted_key = self.dpapi.encrypt_string(api_key)

        # Create key config
        key_config = {
            "key": encrypted_key,
            "tier": tier,
            "enabled": enabled,
            "priority": priority
        }

        if requests_per_minute is not None:
            key_config["requests_per_minute"] = requests_per_minute
        if requests_per_day is not None:
            key_config["requests_per_day"] = requests_per_day
        if requests_per_hour is not None:
            key_config["requests_per_hour"] = requests_per_hour

        # Add to config
        self.config['api_keys'][service].append(key_config)

        # Sort by priority
        self.config['api_keys'][service].sort(key=lambda x: x.get('priority', 99))

        self.save_config()
        return True

    def remove_api_key(self, service: str, index: int) -> bool:
        """
        Remove an API key by index

        Args:
            service: Service name
            index: Index of key to remove (0-based)

        Returns:
            True if successful
        """
        if self.config is None:
            self.load_config()

        service = service.lower()
        if service not in self.config['api_keys']:
            raise ValueError(f"Unknown service: {service}")

        # Handle both array (correct) and dict (corrupted) structures
        api_service_data = self.config['api_keys'][service]

        # If it's a dict (corrupted structure), convert to list first
        if isinstance(api_service_data, dict):
            api_service_data = [api_service_data]
        elif not isinstance(api_service_data, list):
            raise IndexError(f"Invalid key index: {index}")

        if index < 0 or index >= len(api_service_data):
            raise IndexError(f"Invalid key index: {index}")

        # Remove the key from the list
        api_service_data.pop(index)

        # Update the config - if we had a single dict before, we may need to handle the case where list is now empty
        # or convert back to dict if we want to maintain original structure, but it's better to normalize to list
        self.config['api_keys'][service] = api_service_data

        self.save_config()
        return True

    def list_api_keys(self, service: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        List API keys (with keys masked)

        Args:
            service: Service name (None for all)

        Returns:
            Dictionary of service keys with masked key values
        """
        if self.config is None:
            self.load_config()

        result = {}
        services = [service.lower()] if service else self.config['api_keys'].keys()

        for svc in services:
            if svc not in self.config['api_keys']:
                continue

            result[svc] = []

            # Handle both array (correct) and dict (corrupted) structures
            api_service_data = self.config['api_keys'][svc]

            # If it's a dict (corrupted structure), treat it as a single-item list
            if isinstance(api_service_data, dict):
                api_service_data = [api_service_data]
            elif not isinstance(api_service_data, list):
                # If it's neither dict nor list, skip
                continue

            for idx, key_config in enumerate(api_service_data):
                masked_config = key_config.copy()
                # Mask the key
                if key_config.get('key'):
                    masked_config['key'] = "***" + key_config['key'][-8:]
                masked_config['index'] = idx
                result[svc].append(masked_config)

        return result

    def get_api_keys(self, service: str) -> List[Dict[str, Any]]:
        """
        Get decrypted API keys for a service

        Args:
            service: Service name

        Returns:
            List of key configurations with decrypted keys
        """
        if self.config is None:
            self.load_config()

        service = service.lower()
        if service not in self.config['api_keys']:
            return []

        decrypted_keys = []

        # Handle both array (correct) and dict (corrupted) structures
        api_service_data = self.config['api_keys'][service]

        # If it's a dict (corrupted structure), treat it as a single-item list
        if isinstance(api_service_data, dict):
            api_service_data = [api_service_data]
        elif not isinstance(api_service_data, list):
            # If it's neither dict nor list, return empty list
            return []

        for key_config in api_service_data:
            config_copy = key_config.copy()
            config_copy['key'] = self.dpapi.decrypt_string(key_config['key'])
            decrypted_keys.append(config_copy)

        return decrypted_keys

    def get_setting(self, setting_name: str, default=None):
        """Get a configuration setting"""
        if self.config is None:
            self.load_config()
        return self.config['settings'].get(setting_name, default)

    def set_setting(self, setting_name: str, value):
        """Set a configuration setting"""
        if self.config is None:
            self.load_config()

        self.config['settings'][setting_name] = value
        self.save_config()

    def test_api_key(self, service: str, api_key: str) -> Dict[str, Any]:
        """
        Test an API key by making a test request

        Args:
            service: Service name
            api_key: API key to test

        Returns:
            Dictionary with test results
        """
        # Import here to avoid circular dependency
        from api_clients import VirusTotalAPI, HybridAnalysisAPI, AlienVaultOTXAPI, MetaDefenderAPI, AnyRunAPI

        try:
            if service.lower() == "virustotal":
                api = VirusTotalAPI(api_key)
                # Test with a known hash (EICAR test file)
                test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                result = api.lookup_hash(test_hash)

                if result is not None:
                    return {
                        'success': True,
                        'message': f"VirusTotal API key is valid",
                        'tier_info': f"{api.requests_per_minute} req/min, {api.requests_per_day} req/day"
                    }
                else:
                    return {
                        'success': False,
                        'message': "API key test failed - invalid response"
                    }

            elif service.lower() == "hybrid_analysis":
                api = HybridAnalysisAPI(api_key)
                # Test with a known hash
                test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                result = api.lookup_hash(test_hash)

                if result is not None:
                    return {
                        'success': True,
                        'message': f"Hybrid Analysis API key is valid",
                        'tier_info': f"{api.requests_per_minute} req/min, {api.requests_per_hour} req/hour"
                    }
                else:
                    return {
                        'success': False,
                        'message': "API key test failed - invalid response"
                    }

            elif service.lower() == "alienvault_otx":
                api = AlienVaultOTXAPI(api_key)
                # Test with a known hash
                test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                result = api.lookup_hash(test_hash)

                if result is not None:
                    return {
                        'success': True,
                        'message': f"AlienVault OTX API key is valid",
                        'tier_info': f"{api.requests_per_day} req/day"
                    }
                else:
                    return {
                        'success': False,
                        'message': "API key test failed - invalid response"
                    }

            elif service.lower() == "metadefender":
                api = MetaDefenderAPI(api_key)
                # Test with a known hash
                test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                result = api.lookup_hash(test_hash)

                if result is not None:
                    return {
                        'success': True,
                        'message': f"MetaDefender API key is valid",
                        'tier_info': f"{api.requests_per_minute} req/min"
                    }
                else:
                    return {
                        'success': False,
                        'message': "API key test failed - invalid response"
                    }

            elif service.lower() == "any_run":
                api = AnyRunAPI(api_key)
                # Test with a known hash
                test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                result = api.lookup_hash(test_hash)

                if result is not None:
                    return {
                        'success': True,
                        'message': f"Any.Run API key is valid",
                        'tier_info': f"{api.requests_per_minute} req/min"
                    }
                else:
                    return {
                        'success': False,
                        'message': "API key test failed - invalid response"
                    }

            else:
                return {
                    'success': False,
                    'message': f"Unknown service: {service}"
                }

        except Exception as e:
            return {
                'success': False,
                'message': f"API key test failed: {str(e)}"
            }

    def config_exists(self) -> bool:
        """Check if configuration file exists"""
        return self.config_file.exists()

    def get_cache_dir(self) -> Path:
        """Get cache directory path"""
        return self.cache_dir

    def get_log_dir(self) -> Path:
        """Get log directory path"""
        return self.log_dir
