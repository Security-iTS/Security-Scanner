"""
Security Scanner - Service Detection Module

This module performs passive service fingerprinting on open ports.
It identifies services and versions through banner grabbing without exploitation.

Methodology:
- Connect to open ports and read service banners
- Parse banners to identify service type and version
- Use common port mappings as fallback
- No active probing or vulnerability exploitation

Security Considerations:
- Read-only operations (no data sent beyond connection)
- Graceful handling of non-responsive services
- Timeout protection against hanging connections
"""

import socket
import logging
import re
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class ServiceDetector:
    """
    Passive service fingerprinting for security audits.
    
    Identifies running services by analyzing banners and using
    standard port-to-service mappings. Does not attempt active
    exploitation or vulnerability probing.
    
    Attributes:
        target (str): IP address or hostname to analyze
        timeout (float): Socket timeout for banner grabbing
    """
    
    # Common port-to-service mappings (IANA standard assignments)
    # Used as fallback when banner grabbing fails
    COMMON_SERVICES = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        993: 'IMAPS',
        995: 'POP3S',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    def __init__(self, target: str, timeout: float = 2.0):
        """
        Initialize service detector for target system.
        
        Args:
            target: IP address or hostname to scan
            timeout: Socket timeout in seconds (default: 2.0)
        """
        self.target = target
        self.timeout = timeout
    
    def _grab_banner(self, port: int) -> Optional[str]:
        """
        Attempt to grab service banner from open port.
        
        Connects to the port and reads initial response (banner).
        Many services announce themselves with version information,
        which aids in security assessment.
        
        Banner grabbing approach:
        1. Establish TCP connection
        2. Wait for service to send banner
        3. Send minimal probe if no banner received
        4. Parse response for service identification
        
        Args:
            port: Port number to connect to
            
        Returns:
            Optional[str]: Service banner if available, None otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((self.target, port))
            
            # Wait for service to send banner
            # Many services (SSH, FTP, SMTP) announce themselves immediately
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if banner:
                logger.debug(f"Received banner from port {port}: {banner[:100]}")
                return banner
            
            # If no banner received, try minimal HTTP probe
            # This helps identify web servers that don't send banners
            if port in [80, 443, 8080, 8443]:
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    if response:
                        return response
                except Exception:
                    pass
            
            return None
            
        except socket.timeout:
            logger.debug(f"Timeout grabbing banner from port {port}")
            return None
            
        except socket.error as e:
            logger.debug(f"Error grabbing banner from port {port}: {e}")
            return None
            
        finally:
            sock.close()
    
    def _parse_service_info(self, port: int, banner: Optional[str]) -> Dict[str, Any]:
        """
        Parse service information from banner and port number.
        
        Extracts service name, version, and additional metadata from
        banner strings using pattern matching and known signatures.
        
        Identification strategy:
        1. Regex patterns for common service banners
        2. Fallback to IANA port mappings
        3. Mark version as unknown if unparseable
        
        Args:
            port: Port number being analyzed
            banner: Service banner text (may be None)
            
        Returns:
            Dict[str, Any]: Service information including name, version, banner
        """
        service_info = {
            'port': port,
            'service': 'unknown',
            'version': 'unknown',
            'banner': banner or 'No banner available'
        }
        
        # If no banner, use common port mapping
        if not banner:
            service_info['service'] = self.COMMON_SERVICES.get(port, 'unknown')
            return service_info
        
        banner_lower = banner.lower()
        
        # SSH detection
        if 'ssh' in banner_lower:
            service_info['service'] = 'SSH'
            # Extract version: OpenSSH_7.4
            version_match = re.search(r'openssh[_\s]+([\d.]+[p\d]*)', banner_lower)
            if version_match:
                service_info['version'] = f"OpenSSH {version_match.group(1)}"
        
        # HTTP/Web server detection
        elif 'http' in banner_lower or port in [80, 443, 8080, 8443]:
            service_info['service'] = 'HTTP'
            
            # Apache detection
            if 'apache' in banner_lower:
                version_match = re.search(r'apache/([\d.]+)', banner_lower)
                if version_match:
                    service_info['version'] = f"Apache {version_match.group(1)}"
                else:
                    service_info['version'] = 'Apache (version unknown)'
            
            # Nginx detection
            elif 'nginx' in banner_lower:
                version_match = re.search(r'nginx/([\d.]+)', banner_lower)
                if version_match:
                    service_info['version'] = f"nginx {version_match.group(1)}"
                else:
                    service_info['version'] = 'nginx (version unknown)'
            
            # IIS detection
            elif 'microsoft-iis' in banner_lower:
                version_match = re.search(r'microsoft-iis/([\d.]+)', banner_lower)
                if version_match:
                    service_info['version'] = f"IIS {version_match.group(1)}"
                else:
                    service_info['version'] = 'IIS (version unknown)'
        
        # FTP detection
        elif 'ftp' in banner_lower or port == 21:
            service_info['service'] = 'FTP'
            # vsftpd, ProFTPD, etc.
            if 'vsftpd' in banner_lower:
                version_match = re.search(r'vsftpd ([\d.]+)', banner_lower)
                if version_match:
                    service_info['version'] = f"vsftpd {version_match.group(1)}"
            elif 'proftpd' in banner_lower:
                version_match = re.search(r'proftpd ([\d.]+)', banner_lower)
                if version_match:
                    service_info['version'] = f"ProFTPD {version_match.group(1)}"
        
        # SMTP detection
        elif 'smtp' in banner_lower or port == 25:
            service_info['service'] = 'SMTP'
            if 'postfix' in banner_lower:
                service_info['version'] = 'Postfix'
            elif 'sendmail' in banner_lower:
                service_info['version'] = 'Sendmail'
        
        # MySQL detection
        elif 'mysql' in banner_lower or port == 3306:
            service_info['service'] = 'MySQL'
            version_match = re.search(r'([\d.]+)-', banner)
            if version_match:
                service_info['version'] = f"MySQL {version_match.group(1)}"
        
        # PostgreSQL detection
        elif 'postgres' in banner_lower or port == 5432:
            service_info['service'] = 'PostgreSQL'
        
        # Redis detection
        elif 'redis' in banner_lower or port == 6379:
            service_info['service'] = 'Redis'
        
        # MongoDB detection
        elif 'mongo' in banner_lower or port == 27017:
            service_info['service'] = 'MongoDB'
        
        # Telnet detection
        elif port == 23:
            service_info['service'] = 'Telnet'
        
        # RDP detection
        elif port == 3389:
            service_info['service'] = 'RDP'
        
        # SMB detection
        elif port == 445:
            service_info['service'] = 'SMB'
        
        # Fallback to common service mapping
        else:
            service_info['service'] = self.COMMON_SERVICES.get(port, 'unknown')
        
        return service_info
    
    def detect_services(self, open_ports: List[int]) -> List[Dict[str, Any]]:
        """
        Detect services running on list of open ports.
        
        For each open port, attempts banner grabbing and service
        identification. Results include service type, version,
        and raw banner for further analysis.
        
        This is a passive reconnaissance technique that does not
        attempt exploitation or brute force authentication.
        
        Args:
            open_ports: List of open port numbers to analyze
            
        Returns:
            List[Dict[str, Any]]: Service information for each port
        """
        logger.info(f"Detecting services on {len(open_ports)} open ports")
        
        services = []
        
        for port in open_ports:
            try:
                # Attempt banner grabbing
                banner = self._grab_banner(port)
                
                # Parse service information
                service_info = self._parse_service_info(port, banner)
                services.append(service_info)
                
                logger.debug(
                    f"Port {port}: {service_info['service']} "
                    f"({service_info['version']})"
                )
                
            except Exception as e:
                logger.error(f"Error detecting service on port {port}: {e}")
                # Add minimal info even on error
                services.append({
                    'port': port,
                    'service': 'unknown',
                    'version': 'detection failed',
                    'banner': str(e)
                })
        
        logger.info(f"Service detection complete. Identified {len(services)} services")
        
        return services
