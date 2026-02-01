# AGENTS.md

This file provides guidelines for agentic coding agents working with the ADS Scanner codebase.

## Build/Lint/Test Commands

### Python Testing
```bash
# Run all tests
python test_ads_scanner.py

# Run specific test class
python -m unittest test_ads_scanner.TestDPAPIManager -v

# Run single test method
python -m unittest test_ads_scanner.TestDPAPIManager.test_encrypt_decrypt_string -v

# Run with pytest (if available)
pytest test_ads_scanner.py -v
```

### PowerShell Testing
```powershell
# Manual testing required - no automated test framework
# Create test files and verify output matches Python version
```

### Code Quality (Optional)
```bash
# The project uses only standard library, so linting tools are optional
# If you install them, here are the recommended commands:

# With ruff (if installed)
ruff check . --fix
ruff format .

# With black (if installed)  
black *.py

# With mypy (if installed)
mypy *.py --ignore-missing-imports
```

## Code Style Guidelines

### Python Style
- **Python Version**: 3.6+ (uses f-strings, type hints)
- **Line Length**: Maximum 120 characters
- **Indentation**: 4 spaces
- **Quotes**: Double quotes for strings, single for docstring quotes

### Import Organization
```python
# Standard library imports first
import os
import sys
import json
from typing import Dict, List, Optional, Any
from pathlib import Path

# Third-party imports (not used in this project - stdlib only)
# import requests

# Local imports last
from config_manager import ConfigManager
from api_clients import VirusTotalAPI
```

### Type Hints
- Use type hints for all function signatures
- Use Optional[T] for nullable types
- Use Dict[str, Any] for generic dictionaries
- Use Union[T, None] sparingly; prefer Optional[T]

```python
def process_file(
    file_path: Path, 
    api_key: str, 
    proxy: Optional[str] = None
) -> Dict[str, Any]:
    """Process a file and return analysis results."""
```

### Naming Conventions
- **Classes**: PascalCase (e.g., `ConfigManager`, `VirusTotalAPI`)
- **Functions/Methods**: snake_case (e.g., `calculate_combined_risk`)
- **Variables**: snake_case (e.g., `api_key`, `request_count`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `DEFAULT_CACHE_TTL`)
- **Private methods**: Leading underscore (e.g., `_setup_structures`)

### Error Handling
- Use specific exceptions where possible
- Log errors before re-raising when appropriate
- File access errors should be silently ignored for scan continuity
- API errors (401, 403, 429, 404) should be handled specifically

```python
try:
    result = self._make_api_request(file_hash)
except error.HTTPError as e:
    if e.code == 429:  # Rate limit
        time.sleep(60)
        return None
    elif e.code in (401, 403):  # Auth error
        logging.error(f"API key invalid: {e}")
        return None
    elif e.code == 404:  # Not found
        return {'found': False}
    else:
        logging.warning(f"Unexpected API error: {e}")
        return None
```

### Documentation
- Use triple-quoted docstrings for all classes and public methods
- Include Args, Returns, and Raises sections where applicable
- Keep docstrings concise but informative

```python
class APIKeyRotator:
    """Manages rotation of multiple API keys with rate limiting.
    
    Handles automatic key switching when rate limits are reached,
    maintaining request tracking across multiple keys.
    """
    
    def get_next_key(self, service: str) -> Optional[str]:
        """Get the next available API key for a service.
        
        Args:
            service: The service name ('virustotal' or 'hybrid_analysis')
            
        Returns:
            Next available API key or None if all keys are rate limited
        """
```

### Security Requirements
- **NEVER** add functionality to execute or modify discovered streams
- **NEVER** commit API keys or configuration files to version control
- **NEVER** log or expose API keys in error messages
- **ALWAYS** use DPAPI encryption for storing API keys (Windows-specific)
- **ALWAYS** validate user inputs for paths and configurations

### Code Organization Principles
- **Modular Design**: Separate concerns into distinct modules
- **Feature Parity**: Maintain 98% feature parity between Python and PowerShell
- **Stdlib Only**: Use only Python standard library to ensure maximum compatibility
- **Windows-Specific**: Leverage Windows APIs (ctypes) where appropriate
- **Error Suppression**: Silently handle file access errors to allow scans to continue

### Constants and Magic Numbers
```python
# Define constants at module level
DEFAULT_CACHE_TTL_DAYS = 7
VT_API_BASE_URL = "https://www.virustotal.com/api/v3"
MAX_RETRY_ATTEMPTS = 3
RATE_LIMIT_WAIT_SECONDS = 60

# Avoid magic numbers in code
if malicious_count >= 3:  # HIGH risk threshold
    return 'HIGH'
elif threat_score >= 70:  # HA HIGH risk threshold  
    return 'HIGH'
```

### Testing Guidelines
- Write unit tests for all public methods in new modules
- Test both success and failure scenarios
- Use temporary directories for file-based tests
- Mock external API calls in tests
- Test error handling paths specifically

## Project-Specific Requirements

### Feature Parity Maintenance
When adding features or fixing bugs:
1. **Implement in Python first** (easier to test)
2. **Port to PowerShell** maintaining identical logic
3. **Test both implementations** with same data
4. **Compare CSV outputs** - should be nearly identical (except timestamps)

### Configuration Management
- User-specific DPAPI encryption is mandatory
- Configuration location: `%LOCALAPPDATA%\ADSScanner\config.json`
- Support unlimited API keys per service with priority-based rotation
- All settings must have sensible defaults

### API Integration Rules
- Hash-only lookups (never submit file content)
- Respect service-specific rate limits
- Implement automatic retry with exponential backoff for rate limits
- Cache results with configurable TTL (default 7 days)
- Track per-key usage statistics

### Export Format Consistency
- CSV is the primary format (33 columns, backward compatible)
- Include all metadata fields in JSON/HTML/STIX exports
- Maintain consistent risk calculation across all formats
- Provide links to source reports (VT/HA)

---

**Critical**: This is security auditing software. Maintain read-only behavior and never add capabilities to modify or execute discovered alternate data streams.