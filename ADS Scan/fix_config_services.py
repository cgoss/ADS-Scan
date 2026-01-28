#!/usr/bin/env python3
"""
Fix the config to add the metadefender service if it doesn't exist
"""

import json
import os
from pathlib import Path

def fix_config_for_metadefender():
    # Get the config file path
    localappdata = os.environ.get('LOCALAPPDATA', Path.home())
    config_file = Path(localappdata) / 'ADSScanner' / 'config.json'
    
    print(f"Updating config file at: {config_file}")
    
    if config_file.exists():
        print("Loading config file...")
        with open(config_file, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        print("Current API keys structure:")
        for service in data['api_keys']:
            print(f"  {service}: {type(data['api_keys'][service])} with {len(data['api_keys'][service])} keys")
        
        # Add metadefender service if it doesn't exist
        if 'metadefender' not in data['api_keys']:
            print("Adding 'metadefender' service to config...")
            data['api_keys']['metadefender'] = []
        
        # Also add alienvault_otx if it doesn't exist
        if 'alienvault_otx' not in data['api_keys']:
            print("Adding 'alienvault_otx' service to config...")
            data['api_keys']['alienvault_otx'] = []
        
        print("Saving updated config file...")
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print("Config file updated with all services!")
    else:
        print("Config file does not exist")

if __name__ == "__main__":
    fix_config_for_metadefender()