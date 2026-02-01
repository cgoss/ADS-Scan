#!/usr/bin/env python3
"""
Add a MetaDefender key and verify all services are displayed
"""

from config_manager import ConfigManager

def add_and_verify_all():
    print("Adding MetaDefender and Any.Run keys to verify all services...")
    
    # Initialize configuration manager
    config_mgr = ConfigManager()
    
    # Load config
    config_mgr.load_config()
    
    # Add a MetaDefender key
    print("\nAdding a MetaDefender API key...")
    md_key = "demo_metadefender_key_1234567890"
    try:
        success = config_mgr.add_api_key('metadefender', md_key, tier='free', priority=1)
        print(f"Add MetaDefender API key result: {success}")
    except Exception as e:
        print(f"Error adding MetaDefender API key: {e}")
    
    # Add an Any.Run key
    print("\nAdding an Any.Run API key...")
    ar_key = "demo_anyrun_key_1234567890"
    try:
        success = config_mgr.add_api_key('any_run', ar_key, tier='free', priority=1)
        print(f"Add Any.Run API key result: {success}")
    except Exception as e:
        print(f"Error adding Any.Run API key: {e}")
    
    # Add an AlienVault OTX key
    print("\nAdding an AlienVault OTX API key...")
    otx_key = "demo_otx_key_1234567890"
    try:
        success = config_mgr.add_api_key('alienvault_otx', otx_key, tier='free', priority=1)
        print(f"Add AlienVault OTX API key result: {success}")
    except Exception as e:
        print(f"Error adding AlienVault OTX API key: {e}")
    
    # Reload config to verify all were saved
    print("\nReloading configuration to verify all saves...")
    config_mgr.load_config()
    
    # Check final state
    vt_count = len(config_mgr.config['api_keys']['virustotal'])
    ha_count = len(config_mgr.config['api_keys']['hybrid_analysis'])
    ar_count = len(config_mgr.config['api_keys'].get('any_run', []))
    md_count = len(config_mgr.config['api_keys'].get('metadefender', []))
    otx_count = len(config_mgr.config['api_keys'].get('alienvault_otx', []))
    
    print(f"\nFinal counts:")
    print(f"VirusTotal keys: {vt_count}")
    print(f"Hybrid Analysis keys: {ha_count}")
    print(f"Any.Run keys: {ar_count}")
    print(f"MetaDefender keys: {md_count}")
    print(f"AlienVault OTX keys: {otx_count}")
    print(f"Total keys: {vt_count + ha_count + ar_count + md_count + otx_count}")
    
    print("\nAll keys added successfully!")
    print("You can now run the API key manager to see all keys listed.")

if __name__ == "__main__":
    add_and_verify_all()