#!/usr/bin/env python3
"""
Debug script to test the configuration manager
"""

from config_manager import ConfigManager

def test_config():
    print("Testing ConfigManager...")
    
    # Initialize configuration manager
    config_mgr = ConfigManager()
    
    # Check if config exists
    print(f"Config exists: {config_mgr.config_exists()}")
    
    if config_mgr.config_exists():
        try:
            config_mgr.load_config()
            print("Config loaded successfully")

            # Print raw config to see structure
            print("Raw config['api_keys']:", config_mgr.config['api_keys'])
            print("Type of VT keys structure:", type(config_mgr.config['api_keys']['virustotal']))
            if isinstance(config_mgr.config['api_keys']['virustotal'], dict):
                print("VT key content (dict):", config_mgr.config['api_keys']['virustotal'])
            elif isinstance(config_mgr.config['api_keys']['virustotal'], list):
                print("VT keys content (list):", config_mgr.config['api_keys']['virustotal'])

            # Try to list API keys
            all_keys = config_mgr.list_api_keys()
            print(f"All keys retrieved: {all_keys}")

            print("VirusTotal keys:", all_keys.get('virustotal', []))
            print("Hybrid Analysis keys:", all_keys.get('hybrid_analysis', []))

        except Exception as e:
            print(f"Error loading config: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("No config file found. Initializing...")
        config_mgr.initialize()
        print("Initialized. Trying to load...")
        config_mgr.load_config()
        all_keys = config_mgr.list_api_keys()
        print(f"All keys after init: {all_keys}")

if __name__ == "__main__":
    test_config()