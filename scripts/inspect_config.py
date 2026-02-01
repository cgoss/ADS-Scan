#!/usr/bin/env python3
"""
Inspect the actual config file
"""

import json
from pathlib import Path

def inspect_config_file():
    # Get the config file path
    localappdata = Path.home() / '.local' / 'share'  # Fallback
    # On Windows, it would be in LOCALAPPDATA
    import os
    localappdata = os.environ.get('LOCALAPPDATA', Path.home())
    config_file = Path(localappdata) / 'ADSScanner' / 'config.json'
    
    print(f"Looking for config file at: {config_file}")
    
    if config_file.exists():
        print("Config file exists!")
        with open(config_file, 'r', encoding='utf-8-sig') as f:
            try:
                data = json.load(f)
                print("JSON loaded successfully")
                print("Full config structure:")
                print(json.dumps(data, indent=2))
                
                print("\nAPI keys structure:")
                api_keys = data.get('api_keys', {})
                print(f"VirusTotal keys type: {type(api_keys.get('virustotal'))}")
                print(f"Hybrid Analysis keys type: {type(api_keys.get('hybrid_analysis'))}")
                
                if isinstance(api_keys.get('virustotal'), dict):
                    print("ERROR: virustotal is a dict, should be a list!")
                elif isinstance(api_keys.get('virustotal'), list):
                    print(f"VirusTotal has {len(api_keys.get('virustotal', []))} keys")
                    
                if isinstance(api_keys.get('hybrid_analysis'), dict):
                    print("ERROR: hybrid_analysis is a dict, should be a list!")
                elif isinstance(api_keys.get('hybrid_analysis'), list):
                    print(f"Hybrid Analysis has {len(api_keys.get('hybrid_analysis', []))} keys")
                    
            except Exception as e:
                print(f"Error reading JSON: {e}")
    else:
        print("Config file does not exist")

if __name__ == "__main__":
    inspect_config_file()