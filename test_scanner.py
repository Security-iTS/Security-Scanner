"""
Security Scanner - Unit Tests

Demonstrates testing practices for security tools.
Tests scanner components without requiring actual network access.

Run with: python -m pytest test_scanner.py -v
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from scanner.config_checks import ConfigurationChecker


class TestPortScanner(unittest.TestCase):
    """
    Test cases for PortScanner class.
    
    Uses mocking to test logic without network access.
    Validates input validation and error handling.
    """
    
    def test_valid_initialization(self):
        """Test scanner initializes with valid parameters."""
        scanner = PortScanner("127.0.0.1", 1, 1000)
        self.assertEqual(scanner.target, "127.0.0.1")
        self.assertEqual(scanner.port_start, 1)
        self.assertEqual(scanner.port_end, 1000)
    
    def test_invalid_port_range(self):
        """Test scanner rejects invalid port ranges."""
        with self.assertRaises(ValueError):
            PortScanner("127.0.0.1", 1000, 1)  # End < Start
        
        with self.assertRaises(ValueError):
            PortScanner("127.0.0.1", 0, 1000)  # Port < 1
        
        with self.assertRaises(ValueError):
            PortScanner("127.0.0.1", 1, 70000)  # Port > 65535
    
    def test_invalid_timeout(self):
        """Test scanner rejects invalid timeout values."""
        with self.assertRaises(ValueError):
            PortScanner("127.0.0.1", 1, 100, timeout=-1)
    
    @patch('socket.socket')
    def test_check_port_open(self, mock_socket):
        """Test port detection when port is open."""
        # Mock successful connection (port open)
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect_ex.return_value = 0
        mock_socket.return_value = mock_sock_instance
        
        scanner = PortScanner("127.0.0.1", 80, 80)
        result = scanner._check_port(80)
        
        self.assertTrue(result)
        mock_sock_instance.close.assert_called_once()
    
    @patch('socket.socket')
    def test_check_port_closed(self, mock_socket):
        """Test port detection when port is closed."""
        # Mock failed connection (port closed)
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect_ex.return_value = 1
        mock_socket.return_value = mock_sock_instance
        
        scanner = PortScanner("127.0.0.1", 80, 80)
        result = scanner._check_port(80)
        
        self.assertFalse(result)


class TestServiceDetector(unittest.TestCase):
    """
    Test cases for ServiceDetector class.
    
    Validates service identification and banner parsing.
    """
    
    def test_initialization(self):
        """Test service detector initializes correctly."""
        detector = ServiceDetector("127.0.0.1")
        self.assertEqual(detector.target, "127.0.0.1")
    
    def test_parse_ssh_banner(self):
        """Test SSH service detection from banner."""
        detector = ServiceDetector("127.0.0.1")
        banner = "SSH-2.0-OpenSSH_7.4"
        
        service_info = detector._parse_service_info(22, banner)
        
        self.assertEqual(service_info['service'], 'SSH')
        self.assertIn('OpenSSH', service_info['version'])
    
    def test_parse_http_banner(self):
        """Test HTTP service detection from banner."""
        detector = ServiceDetector("127.0.0.1")
        banner = "HTTP/1.1 200 OK\nServer: Apache/2.4.41"
        
        service_info = detector._parse_service_info(80, banner)
        
        self.assertEqual(service_info['service'], 'HTTP')
        self.assertIn('Apache', service_info['version'])
    
    def test_common_service_mapping(self):
        """Test fallback to common port mappings."""
        detector = ServiceDetector("127.0.0.1")
        
        # Test with no banner
        service_info = detector._parse_service_info(22, None)
        self.assertEqual(service_info['service'], 'SSH')
        
        service_info = detector._parse_service_info(3306, None)
        self.assertEqual(service_info['service'], 'MySQL')


class TestConfigurationChecker(unittest.TestCase):
    """
    Test cases for ConfigurationChecker class.
    
    Validates security checks and alert generation.
    """
    
    def test_initialization(self):
        """Test configuration checker initializes correctly."""
        checker = ConfigurationChecker("127.0.0.1")
        self.assertEqual(checker.target, "127.0.0.1")
    
    def test_detect_telnet_insecure(self):
        """Test detection of insecure Telnet protocol."""
        checker = ConfigurationChecker("127.0.0.1")
        service = {
            'port': 23,
            'service': 'Telnet',
            'version': 'unknown',
            'banner': ''
        }
        
        alerts = checker._check_insecure_protocols(service)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['severity'], 'CRITICAL')
        self.assertIn('Telnet', alerts[0]['title'])
    
    def test_detect_ftp_insecure(self):
        """Test detection of insecure FTP protocol."""
        checker = ConfigurationChecker("127.0.0.1")
        service = {
            'port': 21,
            'service': 'FTP',
            'version': 'vsftpd 3.0.3',
            'banner': 'FTP server ready'
        }
        
        alerts = checker._check_insecure_protocols(service)
        
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['severity'], 'HIGH')
    
    def test_detect_database_exposure(self):
        """Test detection of exposed database services."""
        checker = ConfigurationChecker("127.0.0.1")
        
        for db_service, port in [('MySQL', 3306), ('PostgreSQL', 5432), ('MongoDB', 27017)]:
            service = {
                'port': port,
                'service': db_service,
                'version': 'unknown',
                'banner': ''
            }
            
            alerts = checker._check_dangerous_services(service)
            
            self.assertGreater(len(alerts), 0)
            self.assertEqual(alerts[0]['severity'], 'HIGH')
    
    def test_severity_sorting(self):
        """Test that alerts are properly sorted by severity."""
        checker = ConfigurationChecker("127.0.0.1")
        
        services = [
            {'port': 80, 'service': 'HTTP', 'version': 'Apache', 'banner': ''},
            {'port': 23, 'service': 'Telnet', 'version': 'unknown', 'banner': ''},
            {'port': 3306, 'service': 'MySQL', 'version': '5.7', 'banner': ''},
        ]
        
        alerts = checker.check_configurations(services)
        
        # CRITICAL alerts should come first
        if len(alerts) > 0:
            self.assertEqual(alerts[0]['severity'], 'CRITICAL')


class TestIntegration(unittest.TestCase):
    """
    Integration tests for complete scanning workflow.
    
    Tests end-to-end functionality with mocked network calls.
    """
    
    @patch('scanner.port_scanner.PortScanner.scan')
    @patch('scanner.service_detector.ServiceDetector.detect_services')
    @patch('scanner.config_checks.ConfigurationChecker.check_configurations')
    def test_full_scan_workflow(self, mock_config, mock_services, mock_ports):
        """Test complete scan workflow integration."""
        # Mock responses
        mock_ports.return_value = [22, 80]
        mock_services.return_value = [
            {'port': 22, 'service': 'SSH', 'version': 'OpenSSH_7.4', 'banner': 'SSH-2.0-OpenSSH_7.4'},
            {'port': 80, 'service': 'HTTP', 'version': 'Apache', 'banner': 'Apache/2.4'}
        ]
        mock_config.return_value = []
        
        # Execute workflow
        scanner = PortScanner("127.0.0.1", 1, 1000)
        open_ports = scanner.scan()
        
        detector = ServiceDetector("127.0.0.1")
        services = detector.detect_services(open_ports)
        
        checker = ConfigurationChecker("127.0.0.1")
        alerts = checker.check_configurations(services)
        
        # Verify calls
        mock_ports.assert_called_once()
        mock_services.assert_called_once_with([22, 80])
        mock_config.assert_called_once()


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
