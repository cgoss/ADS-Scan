#!/usr/bin/env python3
"""
Fix Broken API Keys
Removes keys that cannot be decrypted (encrypted by different user)
"""

from config_manager import ConfigManager

def fix_broken_keys():
    """Remove all keys that cannot be decrypted"""
    print("=" * 60)
    print("Fix Broken API Keys")
    print("=" * 60)
    print()

    cm = ConfigManager()

    if not cm.config_exists():
        print("[!] No configuration file found")
        return

    try:
        cm.load_config()
        print("[+] Configuration loaded successfully\n")
    except Exception as e:
        print(f"[!] Error loading configuration: {e}")
        return

    services = ['virustotal', 'hybrid_analysis', 'alienvault_otx', 'metadefender', 'any_run']
    broken_keys = []

    # Find all broken keys
    for service in services:
        try:
            masked_keys = cm.list_api_keys(service)[service]
            if not masked_keys:
                continue

            for idx, masked in enumerate(masked_keys):
                try:
                    # Try to decrypt
                    decrypted_keys = cm.get_api_keys(service)
                    if idx >= len(decrypted_keys):
                        broken_keys.append((service, idx, masked['key'], "Index out of range"))
                    else:
                        _ = decrypted_keys[idx]['key']  # Test decryption
                except RuntimeError as e:
                    if "DPAPI" in str(e):
                        broken_keys.append((service, idx, masked['key'], "Encrypted by different user"))
                    else:
                        broken_keys.append((service, idx, masked['key'], str(e)))
                except Exception as e:
                    broken_keys.append((service, idx, masked['key'], str(e)))

        except Exception as e:
            print(f"[!] Error checking {service}: {e}")

    if not broken_keys:
        print("[+] No broken keys found! All keys can be decrypted successfully.")
        return

    # Display broken keys
    print(f"[!] Found {len(broken_keys)} broken key(s):\n")
    for service, idx, masked_key, reason in broken_keys:
        print(f"  {service.upper().replace('_', ' ')} [index {idx}]")
        print(f"    Key: {masked_key}")
        print(f"    Reason: {reason}\n")

    # Ask for confirmation
    response = input("Remove all broken keys? (yes/no): ").strip().lower()
    if response not in ['yes', 'y']:
        print("\n[*] Operation cancelled. No keys were removed.")
        return

    # Remove broken keys (in reverse order to maintain indices)
    removed_count = 0
    broken_keys_by_service = {}

    # Group by service
    for service, idx, masked_key, reason in broken_keys:
        if service not in broken_keys_by_service:
            broken_keys_by_service[service] = []
        broken_keys_by_service[service].append(idx)

    # Remove keys (highest index first to avoid index shifting)
    for service, indices in broken_keys_by_service.items():
        indices_sorted = sorted(indices, reverse=True)
        for idx in indices_sorted:
            try:
                cm.remove_api_key(service, idx)
                print(f"[+] Removed {service} key [index {idx}]")
                removed_count += 1
            except Exception as e:
                print(f"[!] Error removing {service} key [index {idx}]: {e}")

    print(f"\n[+] Successfully removed {removed_count} broken key(s)")
    print("\n" + "=" * 60)
    print("Next Steps:")
    print("=" * 60)
    print("1. Run 'python api_key_manager.py' to add your API keys again")
    print("2. Or use: python scan_ads.py --config add --service <name> --key <key>")
    print("=" * 60)

if __name__ == '__main__':
    fix_broken_keys()
