#!/usr/bin/env python3
"""
Add cross-reference navigation to all markdown documentation files
"""

import os

# Navigation header for different files
navigation = {
    'README.md': """---
**📚 Documentation Navigation**
- 🏠 **[Main README](README.md)** ← You are here
- 🆕 **[What's New in v2.1](WHATS_NEW.md)** - Latest updates and changelog
- 🔑 **[API Key Management](API_KEY_MANAGEMENT.md)** - Configure and manage API keys
- 📦 **[Extraction & Quarantine](EXTRACTION_FEATURE.md)** - Extract suspicious streams for analysis
- ⏭️ **[Resume Feature](RESUME_FEATURE.md)** - Resume interrupted scans
- 🏗️ **[Developer Guide](CLAUDE.md)** - Architecture and development documentation
---

""",
    'WHATS_NEW.md': """---
**📚 Documentation Navigation**
- 🏠 **[Main README](README.md)** - Getting started
- 🆕 **[What's New in v2.1](WHATS_NEW.md)** ← You are here
- 🔑 **[API Key Management](API_KEY_MANAGEMENT.md)** - Configure and manage API keys
- 📦 **[Extraction & Quarantine](EXTRACTION_FEATURE.md)** - Extract suspicious streams for analysis
- ⏭️ **[Resume Feature](RESUME_FEATURE.md)** - Resume interrupted scans
- 🏗️ **[Developer Guide](CLAUDE.md)** - Architecture and development documentation
---

""",
    'API_KEY_MANAGEMENT.md': """---
**📚 Documentation Navigation**
- 🏠 **[Main README](README.md)** - Getting started
- 🆕 **[What's New in v2.1](WHATS_NEW.md)** - Latest updates and changelog
- 🔑 **[API Key Management](API_KEY_MANAGEMENT.md)** ← You are here
- 📦 **[Extraction & Quarantine](EXTRACTION_FEATURE.md)** - Extract suspicious streams for analysis
- ⏭️ **[Resume Feature](RESUME_FEATURE.md)** - Resume interrupted scans
- 🏗️ **[Developer Guide](CLAUDE.md)** - Architecture and development documentation
---

""",
    'EXTRACTION_FEATURE.md': """---
**📚 Documentation Navigation**
- 🏠 **[Main README](README.md)** - Getting started
- 🆕 **[What's New in v2.1](WHATS_NEW.md)** - Latest updates and changelog
- 🔑 **[API Key Management](API_KEY_MANAGEMENT.md)** - Configure and manage API keys
- 📦 **[Extraction & Quarantine](EXTRACTION_FEATURE.md)** ← You are here
- ⏭️ **[Resume Feature](RESUME_FEATURE.md)** - Resume interrupted scans
- 🏗️ **[Developer Guide](CLAUDE.md)** - Architecture and development documentation
---

""",
    'RESUME_FEATURE.md': """---
**📚 Documentation Navigation**
- 🏠 **[Main README](README.md)** - Getting started
- 🆕 **[What's New in v2.1](WHATS_NEW.md)** - Latest updates and changelog
- 🔑 **[API Key Management](API_KEY_MANAGEMENT.md)** - Configure and manage API keys
- 📦 **[Extraction & Quarantine](EXTRACTION_FEATURE.md)** - Extract suspicious streams for analysis
- ⏭️ **[Resume Feature](RESUME_FEATURE.md)** ← You are here
- 🏗️ **[Developer Guide](CLAUDE.md)** - Architecture and development documentation
---

""",
    'CLAUDE.md': """---
**📚 Documentation Navigation**
- 🏠 **[Main README](README.md)** - Getting started
- 🆕 **[What's New in v2.1](WHATS_NEW.md)** - Latest updates and changelog
- 🔑 **[API Key Management](API_KEY_MANAGEMENT.md)** - Configure and manage API keys
- 📦 **[Extraction & Quarantine](EXTRACTION_FEATURE.md)** - Extract suspicious streams for analysis
- ⏭️ **[Resume Feature](RESUME_FEATURE.md)** - Resume interrupted scans
- 🏗️ **[Developer Guide](CLAUDE.md)** ← You are here
---

"""
}

def add_navigation_to_file(filepath, nav_content):
    """Add navigation to a markdown file if not already present"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Check if navigation already exists
    if '📚 Documentation Navigation' in content:
        print(f"  Navigation already exists in {filepath}, skipping...")
        return False

    # Find the first heading
    lines = content.split('\n')
    insert_pos = 0

    for i, line in enumerate(lines):
        if line.startswith('#'):
            insert_pos = i + 1
            break

    # Insert navigation after the first heading
    lines.insert(insert_pos, '\n' + nav_content)

    # Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"  [OK] Added navigation to {filepath}")
    return True

if __name__ == '__main__':
    print("Adding navigation to markdown files...\n")

    updated = 0
    for filename, nav in navigation.items():
        if os.path.exists(filename):
            if add_navigation_to_file(filename, nav):
                updated += 1
        else:
            print(f"  ! File not found: {filename}")

    print(f"\n[OK] Navigation added to {updated} file(s)")
