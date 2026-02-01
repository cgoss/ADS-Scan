#!/usr/bin/env python3
"""
Add another AlienVault OTX key to test multiple keys for the same service
"""

from config_manager import ConfigManager

def add_another_otx_key():
    print("Adding another AlienVault OTX API key to test multiple keys for same service...")
    
    # Initialize configuration manager
    config_mgr = ConfigManager()
    
    # Load config
    config_mgr.load_config()
    
    # Check initial state
    print("\nInitial state:")
    initial_otx_count = len(config_mgr.config['api_keys'].get('alienvault_otx', []))
    print(f"AlienVault OTX keys: {initial_otx_count}")
    
    # Add another AlienVault OTX key with different priority
    print("\nAdding another AlienVault OTX API key...")
    another_otx_key = "another_otx_key_9876543210"
    
    try:
        success = config_mgr.add_api_key('alienvault_otx', another_otx_key, tier='free', priority=2)
        print(f"Add another AlienVault OTX API key result: {success}")
    except Exception as e:
        print(f"Error adding another AlienVault OTX API key: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Reload config to verify it was saved
    print("\nReloading configuration to verify save...")
    config_mgr.load_config()
    
    # Check state after adding
    updated_otx_count = len(config_mgr.config['api_keys'].get('alienvault_otx', []))
    print(f"AlienVault OTX keys after add: {updated_otx_count}")
    
    if updated_otx_count > initial_otx_count:
        print(f"SUCCESS: Another AlienVault OTX API key was added! Count went from {initial_otx_count} to {updated_otx_count}")
        
        # Show details of both keys
        otx_keys = config_mgr.config['api_keys'].get('alienvault_otx', [])
        for i, key in enumerate(otx_keys):
            print(f"  Key {i+1}: Priority {key['priority']}, Tier {key['tier']}")
    else:
        print("FAILURE: Another AlienVault OTX API key was not added!")
    
    print(f"\nTotal keys now: {sum([
        len(config_mgr.config['api_keys']['virustotal']),
        len(config_mgr.config['api_keys']['hybrid_analysis']),
        len(config_mgr.config['api_keys'].get('alienvault_otx', [])),
        len(config_mgr.config['api_keys'].get('metadefender', [])),
        len(config_mgr.config['api_keys'].get('any_run', []))
    ])}")

if __name__ == "__main__":
    add_another_otx_key()