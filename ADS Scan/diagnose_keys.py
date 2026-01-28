#!/usr/bin/env python3
"""
Diagnose API Key Configuration Issues
Checks which keys can/cannot be decrypted
"""

from config_manager import ConfigManager

def diagnose_keys():
    """Check all configured API keys for decryption issues"""
    print("=" * 60)
    print("API Key Configuration Diagnostic")
    print("=" * 60)
    print()

    cm = ConfigManager()

    if not cm.config_exists():
        print("[!] No configuration file found")
        return

    try:
        cm.load_config()
        print("[+] Configuration loaded successfully")
    except Exception as e:
        print(f"[!] Error loading configuration: {e}")
        return

    services = ['virustotal', 'hybrid_analysis', 'alienvault_otx', 'metadefender', 'any_run']

    for service in services:
        print(f"\n{service.upper().replace('_', ' ')}:")
        print("-" * 60)

        # Get masked list
        try:
            masked_keys = cm.list_api_keys(service)[service]
            if not masked_keys:
                print("  No keys configured")
                continue

            print(f"  Found {len(masked_keys)} key(s)")

            # Try to decrypt each key
            for idx, masked in enumerate(masked_keys):
                print(f"\n  Key [{idx}]: {masked['key']}")
                print(f"    Tier: {masked['tier']}, Priority: {masked['priority']}, Enabled: {masked['enabled']}")

                try:
                    decrypted_keys = cm.get_api_keys(service)
                    if idx < len(decrypted_keys):
                        key = decrypted_keys[idx]['key']
                        key_preview = f"{key[:8]}...{key[-4:]}" if len(key) > 12 else key[:8] + "..."
                        print(f"    Decryption: OK - {key_preview}")
                    else:
                        print(f"    Decryption: ERROR - Index out of range")
                except RuntimeError as e:
                    if "DPAPI" in str(e):
                        print(f"    Decryption: FAILED - Encrypted by different user")
                        print(f"    Action Required: Remove and re-add this key")
                    else:
                        print(f"    Decryption: FAILED - {e}")
                except Exception as e:
                    print(f"    Decryption: FAILED - {type(e).__name__}: {e}")

        except Exception as e:
            print(f"  Error: {e}")

    print("\n" + "=" * 60)
    print("Diagnostic Complete")
    print("=" * 60)

if __name__ == '__main__':
    diagnose_keys()
