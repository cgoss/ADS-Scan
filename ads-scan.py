#!/usr/bin/env python3
"""
ADS Scanner - Main Entry Point

This is the main entry point for the ADS Scanner tool.
It imports and runs the scanner from the src package.
"""

import sys
import os

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from ads_scanner import main

if __name__ == '__main__':
    main()
