#!/usr/bin/env python3
"""
API Key Management Interface
Provides a user-friendly interface to view, add, update, and remove API keys
"""

import os
import sys
from config_manager import ConfigManager


def print_header():
    """Print the header for the API key manager"""
    print("=" * 60)
    print("           ADS Scanner v2.1 - API Key Manager")
    print("=" * 60)
    print()


def print_menu():
    """Print the main menu options"""
    print("API Key Management Menu:")
    print("1. View configured API keys")
    print("2. Add a new API key")
    print("3. Update an existing API key")
    print("4. Remove an API key")
    print("5. Test an API key")
    print("6. Exit")
    print()


def display_api_keys(config_mgr):
    """Display all configured API keys"""
    try:
        all_keys = config_mgr.list_api_keys()
        
        print("\nConfigured API Keys:")
        print("-" * 80)
        
        has_keys = False
        
        if all_keys.get('virustotal'):
            print("\nVIRUSTOTAL:")
            for key_info in all_keys['virustotal']:
                status = "ENABLED" if key_info['enabled'] else "DISABLED"
                print(f"  [{key_info['index']}] {key_info['key']} "
                      f"(Tier: {key_info['tier']}, Priority: {key_info['priority']}, Status: {status})")
            has_keys = True
            
        if all_keys.get('hybrid_analysis'):
            print("\nHYBRID ANALYSIS:")
            for key_info in all_keys['hybrid_analysis']:
                status = "ENABLED" if key_info['enabled'] else "DISABLED"
                print(f"  [{key_info['index']}] {key_info['key']} "
                      f"(Tier: {key_info['tier']}, Priority: {key_info['priority']}, Status: {status})")
            has_keys = True
            
        if all_keys.get('alienvault_otx'):
            print("\nALIENVAULT OTX:")
            for key_info in all_keys['alienvault_otx']:
                status = "ENABLED" if key_info['enabled'] else "DISABLED"
                print(f"  [{key_info['index']}] {key_info['key']} "
                      f"(Tier: {key_info['tier']}, Priority: {key_info['priority']}, Status: {status})")
            has_keys = True
            
        if all_keys.get('metadefender'):
            print("\nMETADEFENDER:")
            for key_info in all_keys['metadefender']:
                status = "ENABLED" if key_info['enabled'] else "DISABLED"
                print(f"  [{key_info['index']}] {key_info['key']} "
                      f"(Tier: {key_info['tier']}, Priority: {key_info['priority']}, Status: {status})")
            has_keys = True

        if all_keys.get('any_run'):
            print("\nANY.RUN:")
            for key_info in all_keys['any_run']:
                status = "ENABLED" if key_info['enabled'] else "DISABLED"
                print(f"  [{key_info['index']}] {key_info['key']} "
                      f"(Tier: {key_info['tier']}, Priority: {key_info['priority']}, Status: {status})")
            has_keys = True

        if not has_keys:
            print("  No API keys configured.")

        print("-" * 80)

    except Exception as e:
        print(f"Error displaying API keys: {e}")


def add_api_key(config_mgr):
    """Add a new API key"""
    print("\nAdd New API Key")
    print("-" * 30)

    # Get service
    print("Select service:")
    print("1. VirusTotal")
    print("2. Hybrid Analysis")
    print("3. AlienVault OTX")
    print("4. MetaDefender")
    print("5. Any.Run")

    while True:
        try:
            service_choice = input("Enter choice (1-5): ").strip()
            if service_choice == '1':
                service = 'virustotal'
                break
            elif service_choice == '2':
                service = 'hybrid_analysis'
                break
            elif service_choice == '3':
                service = 'alienvault_otx'
                break
            elif service_choice == '4':
                service = 'metadefender'
                break
            elif service_choice == '5':
                service = 'any_run'
                break
            else:
                print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return
    
    # Get API key
    api_key = input(f"\nEnter {service.replace('_', ' ').title()} API key: ").strip()
    if not api_key:
        print("API key cannot be empty.")
        return
    
    # Get tier for services that support it
    tier = 'free'
    if service in ['virustotal', 'alienvault_otx', 'metadefender', 'any_run']:
        while True:
            tier_input = input("Enter tier (free/paid) [free]: ").strip().lower()
            if not tier_input:
                tier = 'free'
                break
            elif tier_input in ['free', 'paid']:
                tier = tier_input
                break
            else:
                print("Invalid tier. Please enter 'free' or 'paid'.")
    
    # Get priority
    while True:
        try:
            priority_input = input("Enter priority (1-99, lower = higher priority) [99]: ").strip()
            if not priority_input:
                priority = 99
                break
            priority = int(priority_input)
            if 1 <= priority <= 99:
                break
            else:
                print("Priority must be between 1 and 99.")
        except ValueError:
            print("Please enter a valid number.")
    
    # Test the API key before adding
    print(f"\nTesting {service.replace('_', ' ').title()} API key...", end='')
    sys.stdout.flush()
    
    try:
        test_result = config_mgr.test_api_key(service, api_key)
        
        if test_result['success']:
            print(f" SUCCESS! ({test_result['tier_info']})")
            
            # Add the key
            config_mgr.add_api_key(service, api_key, tier=tier, priority=priority)
            print(f"\n[SUCCESS] API key added successfully for {service.replace('_', ' ').title()}!")

            # Show updated list
            display_api_keys(config_mgr)
        else:
            print(f" FAILED: {test_result['message']}")
            print("API key was not added.")

    except Exception as e:
        print(f" FAILED: {e}")
        print("API key was not added.")


def update_api_key(config_mgr):
    """Update an existing API key"""
    print("\nUpdate Existing API Key")
    print("-" * 30)

    # First, show current keys
    display_api_keys(config_mgr)

    # Get service
    print("\nSelect service:")
    print("1. VirusTotal")
    print("2. Hybrid Analysis")
    print("3. AlienVault OTX")
    print("4. MetaDefender")
    print("5. Any.Run")

    while True:
        try:
            service_choice = input("Enter choice (1-5): ").strip()
            if service_choice == '1':
                service = 'virustotal'
                break
            elif service_choice == '2':
                service = 'hybrid_analysis'
                break
            elif service_choice == '3':
                service = 'alienvault_otx'
                break
            elif service_choice == '4':
                service = 'metadefender'
                break
            elif service_choice == '5':
                service = 'any_run'
                break
            else:
                print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return
    
    # Get current keys for the service
    keys = config_mgr.list_api_keys(service)[service]
    if not keys:
        print(f"\nNo {service.replace('_', ' ').title()} keys configured.")
        return
    
    # Show available keys
    print(f"\nAvailable {service.replace('_', ' ').title()} keys:")
    for key_info in keys:
        status = "ENABLED" if key_info['enabled'] else "DISABLED"
        print(f"  [{key_info['index']}] {key_info['key']} "
              f"(Tier: {key_info['tier']}, Priority: {key_info['priority']}, Status: {status})")
    
    # Get key index to update
    while True:
        try:
            index_input = input(f"\nEnter the index of the key to update (0-{len(keys)-1}): ").strip()
            index = int(index_input)
            if 0 <= index < len(keys):
                break
            else:
                print(f"Invalid index. Please enter a number between 0 and {len(keys)-1}.")
        except ValueError:
            print("Please enter a valid number.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return
    
    # Get new API key
    new_api_key = input(f"\nEnter new {service.replace('_', ' ').title()} API key: ").strip()
    if not new_api_key:
        print("API key cannot be empty.")
        return
    
    # Get new tier for services that support it
    tier = keys[index]['tier']  # Default to existing tier
    if service in ['virustotal', 'alienvault_otx', 'metadefender', 'any_run']:
        while True:
            tier_input = input(f"Enter new tier (free/paid) [{tier}]: ").strip().lower()
            if not tier_input:
                break  # Keep existing tier
            elif tier_input in ['free', 'paid']:
                tier = tier_input
                break
            else:
                print("Invalid tier. Please enter 'free' or 'paid'.")
    
    # Get new priority
    priority = keys[index]['priority']  # Default to existing priority
    while True:
        try:
            priority_input = input(f"Enter new priority (1-99) [{priority}]: ").strip()
            if not priority_input:
                break  # Keep existing priority
            priority = int(priority_input)
            if 1 <= priority <= 99:
                break
            else:
                print("Priority must be between 1 and 99.")
        except ValueError:
            print("Please enter a valid number.")
    
    # Test the new API key before updating
    print(f"\nTesting new {service.replace('_', ' ').title()} API key...", end='')
    sys.stdout.flush()
    
    try:
        test_result = config_mgr.test_api_key(service, new_api_key)
        
        if test_result['success']:
            print(f" SUCCESS! ({test_result['tier_info']})")
            
            # Remove the old key
            config_mgr.remove_api_key(service, index)
            
            # Add the new key with same or updated settings
            config_mgr.add_api_key(service, new_api_key, tier=tier, priority=priority)
            print(f"\n[SUCCESS] API key updated successfully for {service.replace('_', ' ').title()}!")

            # Show updated list
            display_api_keys(config_mgr)
        else:
            print(f" FAILED: {test_result['message']}")
            print("API key was not updated.")

    except Exception as e:
        print(f" FAILED: {e}")
        print("API key was not updated.")


def remove_api_key(config_mgr):
    """Remove an API key"""
    print("\nRemove API Key")
    print("-" * 20)
    
    # First, show current keys
    display_api_keys(config_mgr)
    
    # Get service
    print("\nSelect service:")
    print("1. VirusTotal")
    print("2. Hybrid Analysis")
    print("3. AlienVault OTX")
    print("4. MetaDefender")
    print("5. Any.Run")

    while True:
        try:
            service_choice = input("Enter choice (1-5): ").strip()
            if service_choice == '1':
                service = 'virustotal'
                break
            elif service_choice == '2':
                service = 'hybrid_analysis'
                break
            elif service_choice == '3':
                service = 'alienvault_otx'
                break
            elif service_choice == '4':
                service = 'metadefender'
                break
            elif service_choice == '5':
                service = 'any_run'
                break
            else:
                print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return
    
    # Get current keys for the service
    keys = config_mgr.list_api_keys(service)[service]
    if not keys:
        print(f"\nNo {service.replace('_', ' ').title()} keys configured.")
        return
    
    # Show available keys
    print(f"\nAvailable {service.replace('_', ' ').title()} keys:")
    for key_info in keys:
        status = "ENABLED" if key_info['enabled'] else "DISABLED"
        print(f"  [{key_info['index']}] {key_info['key']} "
              f"(Tier: {key_info['tier']}, Priority: {key_info['priority']}, Status: {status})")
    
    # Get key index to remove
    while True:
        try:
            index_input = input(f"\nEnter the index of the key to remove (0-{len(keys)-1}): ").strip()
            index = int(index_input)
            if 0 <= index < len(keys):
                break
            else:
                print(f"Invalid index. Please enter a number between 0 and {len(keys)-1}.")
        except ValueError:
            print("Please enter a valid number.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return
    
    # Confirm removal
    confirm = input(f"\nAre you sure you want to remove key [{index}]? (yes/no): ").strip().lower()
    if confirm not in ['yes', 'y']:
        print("Removal cancelled.")
        return
    
    try:
        config_mgr.remove_api_key(service, index)
        print(f"\n[SUCCESS] API key removed successfully from {service.replace('_', ' ').title()}!")

        # Show updated list
        display_api_keys(config_mgr)
    except Exception as e:
        print(f"\n[ERROR] Error removing API key: {e}")


def test_api_key(config_mgr):
    """Test an API key without adding it"""
    print("\nTest API Key")
    print("-" * 15)

    # Ask user if they want to test an existing key or enter a new one
    print("How would you like to test?")
    print("1. Test an existing configured API key")
    print("2. Test a new API key (enter manually)")

    while True:
        try:
            mode_choice = input("Enter choice (1-2): ").strip()
            if mode_choice == '1':
                # Test existing key
                return test_existing_api_key(config_mgr)
            elif mode_choice == '2':
                # Test new key
                return test_new_api_key(config_mgr)
            else:
                print("Invalid choice. Please enter 1 or 2.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return


def test_existing_api_key(config_mgr):
    """Test an existing configured API key"""
    print("\nSelect service to test existing key:")
    print("1. VirusTotal")
    print("2. Hybrid Analysis")
    print("3. AlienVault OTX")
    print("4. MetaDefender")
    print("5. Any.Run")

    service_map = {
        '1': 'virustotal',
        '2': 'hybrid_analysis',
        '3': 'alienvault_otx',
        '4': 'metadefender',
        '5': 'any_run'
    }

    while True:
        try:
            service_choice = input("Enter choice (1-5): ").strip()
            if service_choice in service_map:
                service = service_map[service_choice]
                service_name = service.replace('_', ' ').title()
                break
            else:
                print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return

    # Get existing keys for the service
    keys = config_mgr.list_api_keys(service)[service]
    if not keys:
        print(f"\nNo {service_name} keys configured.")
        return

    # Show available keys
    print(f"\nAvailable {service_name} keys:")
    for key_info in keys:
        status = "ENABLED" if key_info['enabled'] else "DISABLED"
        print(f"  [{key_info['index']}] {key_info['key']} "
              f"(Tier: {key_info['tier']}, Priority: {key_info['priority']}, Status: {status})")

    # Get key index to test
    while True:
        try:
            max_index = len(keys) - 1
            index_input = input(f"\nEnter the index of the key to test (0-{max_index}): ").strip()
            index = int(index_input)
            if 0 <= index <= max_index:
                break
            else:
                print(f"Invalid index. Please enter a number between 0 and {max_index}.")
        except ValueError:
            print("Please enter a valid number.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return

    # Get the selected key and decrypt it
    selected_key = keys[index]

    print(f"\nDecrypting {service_name} API key [index {index}]...", end='')
    sys.stdout.flush()

    try:
        decrypted_keys = config_mgr.get_api_keys(service)
        if index >= len(decrypted_keys):
            print(f" FAILED!")
            print(f"\n[ERROR] Key index {index} not found in decrypted keys list")
            return

        decrypted_key = decrypted_keys[index]['key']
        print(" OK")

    except RuntimeError as e:
        print(f" FAILED!")
        if "DPAPI" in str(e):
            print(f"\n[ERROR] Cannot decrypt API key - it was encrypted by a different Windows user")
            print(f"[ERROR] You must add the API key again from this user account")
        else:
            print(f"\n[ERROR] Decryption error: {e}")
        return
    except Exception as e:
        print(f" FAILED!")
        print(f"\n[ERROR] Error decrypting API key: {e}")
        return

    print(f"Testing {service_name} API key...", end='')
    sys.stdout.flush()

    try:
        test_result = config_mgr.test_api_key(service, decrypted_key)

        if test_result['success']:
            print(f" SUCCESS!")
            print(f"\n[SUCCESS] {test_result['message']}")
            print(f"[SUCCESS] Rate limits: {test_result['tier_info']}")
        else:
            print(f" FAILED!")
            print(f"\n[ERROR] {test_result['message']}")

    except Exception as e:
        print(f" FAILED!")
        print(f"\n[ERROR] Error testing API key: {e}")


def test_new_api_key(config_mgr):
    """Test a new API key entered manually"""
    print("\nSelect service:")
    print("1. VirusTotal")
    print("2. Hybrid Analysis")
    print("3. AlienVault OTX")
    print("4. MetaDefender")
    print("5. Any.Run")

    service_map = {
        '1': 'virustotal',
        '2': 'hybrid_analysis',
        '3': 'alienvault_otx',
        '4': 'metadefender',
        '5': 'any_run'
    }

    while True:
        try:
            service_choice = input("Enter choice (1-5): ").strip()
            if service_choice in service_map:
                service = service_map[service_choice]
                service_name = service.replace('_', ' ').title()
                break
            else:
                print("Invalid choice. Please enter 1, 2, 3, 4, or 5.")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return

    # Get API key to test
    api_key = input(f"\nEnter {service_name} API key to test: ").strip()
    if not api_key:
        print("API key cannot be empty.")
        return

    print(f"\nTesting {service_name} API key...", end='')
    sys.stdout.flush()

    try:
        test_result = config_mgr.test_api_key(service, api_key)

        if test_result['success']:
            print(f" SUCCESS!")
            print(f"\n[SUCCESS] {test_result['message']}")
            print(f"[SUCCESS] Rate limits: {test_result['tier_info']}")
        else:
            print(f" FAILED!")
            print(f"\n[ERROR] {test_result['message']}")

    except Exception as e:
        print(f" FAILED!")
        print(f"\n[ERROR] Error testing API key: {e}")


def main():
    """Main function for the API key manager interface"""
    print_header()
    
    # Initialize configuration manager
    config_mgr = ConfigManager()
    
    # Initialize config if it doesn't exist
    if not config_mgr.config_exists():
        print("[!] No configuration file found. Creating default configuration...")
        config_mgr.initialize()
        print("[SUCCESS] Default configuration created.")
    else:
        try:
            config_mgr.load_config()
            print("[SUCCESS] Configuration loaded successfully.")
        except Exception as e:
            print(f"[X] Error loading configuration: {e}")
            print("Creating new configuration...")
            config_mgr.initialize()
    
    print()
    
    while True:
        print_menu()
        
        try:
            choice = input("Enter your choice (1-6): ").strip()
            
            if choice == '1':
                display_api_keys(config_mgr)
            elif choice == '2':
                add_api_key(config_mgr)
            elif choice == '3':
                update_api_key(config_mgr)
            elif choice == '4':
                remove_api_key(config_mgr)
            elif choice == '5':
                test_api_key(config_mgr)
            elif choice == '6':
                print("\nGoodbye!")
                break
            else:
                print("\n[!] Invalid choice. Please enter a number between 1 and 6.")
        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except EOFError:
            print("\n\nGoodbye!")
            break
        
        print("\n" + "="*60 + "\n")


if __name__ == '__main__':
    main()