#!/usr/bin/env python3
"""
Fix the config to add the any_run service if it doesn't exist
"""

import json
import os
from pathlib import Path

def fix_config_for_anyrun():
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
        
        # Add any_run service if it doesn't exist
        if 'any_run' not in data['api_keys']:
            print("Adding 'any_run' service to config...")
            data['api_keys']['any_run'] = []
        
        print("Saving updated config file...")
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print("Config file updated with Any.Run service!")
    else:
        print("Config file does not exist")

if __name__ == "__main__":
    fix_config_for_anyrun()