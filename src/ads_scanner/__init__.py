"""
ADS Scanner - NTFS Alternate Data Stream Security Auditing Tool
Version: 2.1

A comprehensive security auditing tool for detecting, analyzing, and quarantining
hidden threats in Windows NTFS Alternate Data Streams.
"""

__version__ = "2.1.0"
__author__ = "ADS Scanner Team"
__license__ = "MIT"

from .scanner import main

__all__ = ['main']
