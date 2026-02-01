#!/usr/bin/env python3
"""
Fix the config file structure to convert single objects to arrays
"""

import json
import os
from pathlib import Path

def fix_config_structure():
    # Get the config file path
    localappdata = os.environ.get('LOCALAPPDATA', Path.home())
    config_file = Path(localappdata) / 'ADSScanner' / 'config.json'
    
    print(f"Fixing config file at: {config_file}")
    
    if config_file.exists():
        print("Loading config file...")
        with open(config_file, 'r', encoding='utf-8-sig') as f:
            data = json.load(f)
        
        print("Current structure:")
        print(f"VirusTotal type: {type(data['api_keys']['virustotal'])}")
        print(f"Hybrid Analysis type: {type(data['api_keys']['hybrid_analysis'])}")
        
        # Fix the structure if it's in the corrupted format
        fixed = False
        
        if isinstance(data['api_keys']['virustotal'], dict):
            print("Converting VirusTotal from dict to list...")
            data['api_keys']['virustotal'] = [data['api_keys']['virustotal']]
            fixed = True
        
        if isinstance(data['api_keys']['hybrid_analysis'], dict):
            print("Converting Hybrid Analysis from dict to list...")
            data['api_keys']['hybrid_analysis'] = [data['api_keys']['hybrid_analysis']]
            fixed = True
            
        if isinstance(data['api_keys'].get('alienvault_otx'), dict):
            print("Converting AlienVault OTX from dict to list...")
            data['api_keys']['alienvault_otx'] = [data['api_keys']['alienvault_otx']] if data['api_keys']['alienvault_otx'] else []
            fixed = True
            
        if isinstance(data['api_keys'].get('metadefender'), dict):
            print("Converting MetaDefender from dict to list...")
            data['api_keys']['metadefender'] = [data['api_keys']['metadefender']] if data['api_keys']['metadefender'] else []
            fixed = True
        
        if fixed:
            print("Saving fixed config file...")
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            print("Config file structure fixed!")
        else:
            print("Config file already has correct structure.")
    else:
        print("Config file does not exist")

if __name__ == "__main__":
    fix_config_structure()