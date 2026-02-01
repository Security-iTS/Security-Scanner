"""
Security Scanner - Scanner Package

This package provides passive security scanning capabilities for
authorized network security assessments.

Modules:
- port_scanner: TCP port scanning functionality
- service_detector: Service fingerprinting and version detection
- config_checks: Security configuration analysis

Ethical Use Only:
This tool must only be used on systems you own or have explicit
written permission to test. Unauthorized scanning may be illegal.
"""

from .port_scanner import PortScanner
from .service_detector import ServiceDetector
from .config_checks import ConfigurationChecker

__all__ = ['PortScanner', 'ServiceDetector', 'ConfigurationChecker']
__version__ = '1.0.0'
