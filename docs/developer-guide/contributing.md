# Contributing to ADS Scanner

Thank you for your interest in contributing to ADS Scanner!

## Project Structure

```
ADS-Scan/
├── ads-scan.py              # Main entry point
├── src/ads_scanner/         # Source code
│   ├── scanner.py          # Core scanner logic
│   ├── config_manager.py   # Configuration management
│   ├── key_rotator.py      # API key rotation
│   ├── api/                # API client implementations
│   ├── cache/              # Results caching
│   └── export/             # Export format handlers
├── powershell/             # PowerShell implementation
├── scripts/                # Utility scripts
├── docs/                   # Documentation
├── tests/                  # Test files
└── examples/               # Example usage

```

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/cgoss/ADS-Scan.git
   cd ADS-Scan
   ```

2. Run tests (when available):
   ```bash
   python -m pytest tests/
   ```

## Code Style

- Follow PEP 8 for Python code
- Use descriptive variable names
- Add docstrings to all functions and classes
- Keep functions focused and under 50 lines when possible

## Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes

3. Test your changes:
   ```bash
   python ads-scan.py --help
   python ads-scan.py C:\Test --use-config
   ```

4. Commit with descriptive messages:
   ```bash
   git commit -m "Add: description of your changes"
   ```

5. Push and create a pull request:
   ```bash
   git push origin feature/your-feature-name
   ```

## Pull Request Guidelines

- Describe what your PR does
- Reference any related issues
- Include examples of usage if adding features
- Update documentation if needed
- Maintain backwards compatibility when possible

## Adding New Features

### Adding a New API Service

1. Create API client in `src/ads_scanner/api/clients.py`
2. Add service to `config_manager.py`
3. Update `key_rotator.py` to support the service
4. Add documentation
5. Update README with service details

### Adding Export Formats

1. Add export function to `src/ads_scanner/export/formats.py`
2. Update argument parser in `scanner.py`
3. Add examples to documentation

## Testing

- Test on Windows with NTFS filesystem
- Test with multiple API services
- Test error handling (invalid keys, network issues)
- Test with large directories
- Test extraction functionality

## Documentation

When adding features, update:
- `README.md` - If it affects main usage
- `docs/user-guide/` - For user-facing features
- `docs/developer-guide/` - For architectural changes
- `docs/changelog.md` - Always update the changelog

## Code Review Process

All submissions require review. We use GitHub pull requests for this purpose.

## Reporting Bugs

Create an issue with:
- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS
- Error messages (if any)

## Feature Requests

Create an issue with:
- Use case description
- Expected behavior
- Why it would be useful

## Questions?

- Open an issue for questions
- Check existing issues first
- Be respectful and constructive

Thank you for contributing!
