"""
Core module for SecureScan
Contains fundamental scanning functionality
"""

from .ports import ScanType, PortState, COMMON_PORTS
from .network import get_service_banner

__all__ = ['ScanType', 'PortState', 'COMMON_PORTS', 'get_service_banner']
