#!/usr/bin/env python3
"""
Add a new API key to demonstrate the functionality
"""

from config_manager import ConfigManager

def add_demo_key():
    print("Adding a demo API key to show the functionality...")
    
    # Initialize configuration manager
    config_mgr = ConfigManager()
    
    # Load config
    config_mgr.load_config()
    
    # Add a demo key to Any.Run service
    print("\nAdding a demo Any.Run API key...")
    demo_key = "demo_anyrun_key_1234567890"
    
    try:
        success = config_mgr.add_api_key('any_run', demo_key, tier='free', priority=1)
        print(f"Add API key result: {success}")
    except Exception as e:
        print(f"Error adding API key: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Reload config to verify it was saved
    print("\nReloading configuration to verify save...")
    config_mgr.load_config()
    
    # Check state after adding
    vt_count = len(config_mgr.config['api_keys']['virustotal'])
    ha_count = len(config_mgr.config['api_keys']['hybrid_analysis'])
    ar_count = len(config_mgr.config['api_keys'].get('any_run', []))
    
    print(f"VirusTotal keys: {vt_count}")
    print(f"Hybrid Analysis keys: {ha_count}")
    print(f"Any.Run keys: {ar_count}")
    print(f"Total keys: {vt_count + ha_count + ar_count}")
    
    print("\nDemo key added successfully!")
    print("You can now run the API key manager to see the new key listed.")

if __name__ == "__main__":
    add_demo_key()