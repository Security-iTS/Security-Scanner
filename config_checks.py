"""
Security Scanner - Configuration Security Checker

This module analyzes detected services for common security misconfigurations
and potential vulnerabilities based on industry best practices.

Focus Areas:
- Insecure protocols (Telnet, FTP, HTTP)
- Outdated software versions with known CVEs
- Weak default configurations
- Unnecessary services exposure

Approach:
- Purely analytical (no exploitation)
- Risk-based severity ratings
- Actionable remediation guidance
- CVE database references where applicable
"""

import logging
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class ConfigurationChecker:
    """
    Security configuration analyzer for detected services.
    
    Evaluates service configurations against security best practices
    and identifies potential risks. Does not perform active testing
    or exploitation.
    
    Severity Levels:
    - CRITICAL: Immediate action required (e.g., Telnet exposed)
    - HIGH: Significant risk (e.g., outdated SSH version)
    - MEDIUM: Security improvement recommended (e.g., HTTP instead of HTTPS)
    - LOW: Minor security enhancement (e.g., verbose banners)
    
    Attributes:
        target (str): IP address or hostname being analyzed
    """
    
    # Known vulnerable versions (simplified - production would use CVE database)
    # Format: {service: {version_pattern: (severity, description, cve_ref)}}
    VULNERABLE_VERSIONS = {
        'OpenSSH': {
            '7.4': ('HIGH', 'Multiple vulnerabilities including user enumeration', 'CVE-2018-15473'),
            '7.2': ('CRITICAL', 'Remote code execution vulnerability', 'CVE-2016-6210'),
            '6.': ('CRITICAL', 'Multiple critical vulnerabilities', 'Multiple CVEs'),
        },
        'Apache': {
            '2.4.49': ('CRITICAL', 'Path traversal and RCE vulnerability', 'CVE-2021-41773'),
            '2.4.7': ('HIGH', 'Multiple vulnerabilities including DoS', 'Multiple CVEs'),
            '2.2.': ('HIGH', 'End of life version with unpatched vulnerabilities', 'N/A'),
        },
        'nginx': {
            '1.17.': ('MEDIUM', 'Older version, upgrade recommended', 'N/A'),
            '1.10.': ('HIGH', 'Multiple known vulnerabilities', 'Multiple CVEs'),
        }
    }
    
    def __init__(self, target: str):
        """
        Initialize configuration checker for target system.
        
        Args:
            target: IP address or hostname being analyzed
        """
        self.target = target
    
    def _check_insecure_protocols(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Identify services using insecure or deprecated protocols.
        
        Insecure protocols transmit data in cleartext or use weak
        authentication, making them vulnerable to interception and
        man-in-the-middle attacks.
        
        Flagged protocols:
        - Telnet: Unencrypted remote access
        - FTP: Cleartext credentials and data
        - HTTP: Unencrypted web traffic (especially for sensitive data)
        - SMTP (unencrypted): Email without TLS
        
        Args:
            service: Service information dictionary
            
        Returns:
            List[Dict[str, Any]]: Security alerts for insecure protocols
        """
        alerts = []
        service_name = service.get('service', '').upper()
        port = service.get('port')
        
        # Telnet: Critical security risk
        if service_name == 'TELNET':
            alerts.append({
                'severity': 'CRITICAL',
                'title': 'Insecure Protocol: Telnet Detected',
                'description': (
                    f"Telnet service detected on port {port}. Telnet transmits all data, "
                    "including passwords, in cleartext. This allows attackers to intercept "
                    "credentials and session data."
                ),
                'recommendation': (
                    "Disable Telnet immediately. Use SSH (port 22) for secure remote access. "
                    "SSH provides encryption and strong authentication."
                ),
                'port': port,
                'service': service_name
            })
        
        # FTP: High security risk
        elif service_name == 'FTP':
            alerts.append({
                'severity': 'HIGH',
                'title': 'Insecure Protocol: FTP Detected',
                'description': (
                    f"FTP service detected on port {port}. Standard FTP transmits credentials "
                    "and data in cleartext, vulnerable to packet sniffing and credential theft."
                ),
                'recommendation': (
                    "Replace with SFTP (SSH File Transfer Protocol) or FTPS (FTP over TLS). "
                    "If FTP must be used, enable TLS encryption (FTPS)."
                ),
                'port': port,
                'service': service_name
            })
        
        # HTTP on common web ports
        elif service_name == 'HTTP' and port in [80, 8080]:
            alerts.append({
                'severity': 'MEDIUM',
                'title': 'Unencrypted HTTP Service',
                'description': (
                    f"HTTP service detected on port {port} without TLS encryption. "
                    "Traffic is transmitted in cleartext, exposing sensitive data and "
                    "enabling man-in-the-middle attacks."
                ),
                'recommendation': (
                    "Implement HTTPS with TLS 1.2 or higher. Obtain SSL/TLS certificate "
                    "from trusted CA. Redirect HTTP traffic to HTTPS. Consider HSTS header."
                ),
                'port': port,
                'service': service_name
            })
        
        # SMTP without TLS indication
        elif service_name == 'SMTP' and 'tls' not in service.get('banner', '').lower():
            alerts.append({
                'severity': 'MEDIUM',
                'title': 'Potentially Unencrypted SMTP',
                'description': (
                    f"SMTP service on port {port} may not support TLS encryption. "
                    "Email transmission without encryption exposes message content and credentials."
                ),
                'recommendation': (
                    "Enable STARTTLS on SMTP server. Verify TLS configuration. "
                    "Consider using submission port 587 with mandatory TLS."
                ),
                'port': port,
                'service': service_name
            })
        
        return alerts
    
    def _check_vulnerable_versions(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check for known vulnerable software versions.
        
        Compares detected service versions against database of known
        vulnerabilities. In production, this would integrate with
        NVD (National Vulnerability Database) or similar CVE sources.
        
        Version matching strategy:
        - Exact version match (e.g., "2.4.49")
        - Prefix match for version families (e.g., "6." for all 6.x)
        - Known EOL (End of Life) versions
        
        Args:
            service: Service information dictionary
            
        Returns:
            List[Dict[str, Any]]: Security alerts for vulnerable versions
        """
        alerts = []
        version = service.get('version', 'unknown')
        
        # Skip if version couldn't be determined
        if version == 'unknown' or 'version unknown' in version.lower():
            return alerts
        
        # Check each known vulnerable software
        for software, vulnerabilities in self.VULNERABLE_VERSIONS.items():
            if software in version:
                # Check for version-specific vulnerabilities
                for vuln_version, (severity, description, cve) in vulnerabilities.items():
                    if vuln_version in version:
                        alerts.append({
                            'severity': severity,
                            'title': f'Vulnerable {software} Version Detected',
                            'description': (
                                f"{software} {version} detected on port {service['port']}. "
                                f"Known issue: {description}"
                            ),
                            'recommendation': (
                                f"Upgrade {software} to latest stable version. "
                                f"Review security advisories. CVE reference: {cve}"
                            ),
                            'port': service['port'],
                            'service': service['service'],
                            'cve': cve
                        })
                        break  # Only report most specific match
        
        return alerts
    
    def _check_dangerous_services(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Identify services that are inherently risky when exposed.
        
        Certain services should never be exposed to untrusted networks
        due to their design or common attack vectors.
        
        High-risk services:
        - Database ports (MySQL, PostgreSQL, MongoDB, Redis)
        - Remote desktop (RDP, VNC)
        - File sharing (SMB)
        - Unprotected administrative interfaces
        
        Args:
            service: Service information dictionary
            
        Returns:
            List[Dict[str, Any]]: Security alerts for risky service exposure
        """
        alerts = []
        service_name = service.get('service', '').upper()
        port = service.get('port')
        
        # Database services exposed
        if service_name in ['MYSQL', 'POSTGRESQL', 'MONGODB', 'REDIS']:
            alerts.append({
                'severity': 'HIGH',
                'title': f'Database Service Exposed: {service_name}',
                'description': (
                    f"{service_name} database detected on port {port}. Database services "
                    "should not be directly accessible from untrusted networks. "
                    "Common attack vectors include brute force, default credentials, "
                    "and unpatched vulnerabilities."
                ),
                'recommendation': (
                    f"Restrict {service_name} access to localhost or trusted IP ranges only. "
                    "Use firewall rules to block external access. Enable authentication. "
                    "Use VPN for remote database access. Monitor for failed login attempts."
                ),
                'port': port,
                'service': service_name
            })
        
        # Remote Desktop Protocol
        elif service_name == 'RDP':
            alerts.append({
                'severity': 'HIGH',
                'title': 'Remote Desktop (RDP) Exposed',
                'description': (
                    f"RDP service detected on port {port}. RDP is frequently targeted "
                    "for brute force attacks and has history of critical vulnerabilities "
                    "(e.g., BlueKeep CVE-2019-0708)."
                ),
                'recommendation': (
                    "Do not expose RDP to the internet. Use VPN for remote access. "
                    "Enable Network Level Authentication (NLA). Implement account lockout policies. "
                    "Use strong passwords and consider multi-factor authentication."
                ),
                'port': port,
                'service': service_name
            })
        
        # SMB file sharing
        elif service_name == 'SMB':
            alerts.append({
                'severity': 'HIGH',
                'title': 'SMB File Sharing Exposed',
                'description': (
                    f"SMB service detected on port {port}. SMB has been target of major "
                    "attacks (WannaCry, NotPetya). Exposed SMB allows network enumeration "
                    "and potential unauthorized file access."
                ),
                'recommendation': (
                    "Block SMB ports (445, 139) at network perimeter. Disable SMBv1. "
                    "Require authentication for all shares. Use VPN for remote file access. "
                    "Keep Windows systems fully patched."
                ),
                'port': port,
                'service': service_name
            })
        
        # VNC remote access
        elif service_name == 'VNC':
            alerts.append({
                'severity': 'MEDIUM',
                'title': 'VNC Remote Access Exposed',
                'description': (
                    f"VNC service detected on port {port}. VNC typically uses weak "
                    "authentication and may transmit data unencrypted. Vulnerable to "
                    "password brute force and session hijacking."
                ),
                'recommendation': (
                    "Do not expose VNC to internet. Use SSH tunneling for VNC connections. "
                    "Enable strong VNC passwords. Consider using more secure alternatives "
                    "like SSH with X11 forwarding."
                ),
                'port': port,
                'service': service_name
            })
        
        return alerts
    
    def _check_information_disclosure(self, service: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Identify excessive information disclosure in service banners.
        
        Verbose banners revealing exact software versions aid attackers
        in targeting specific vulnerabilities. While not directly
        exploitable, this is defense-in-depth concern.
        
        Information disclosure issues:
        - Detailed version numbers in banners
        - Operating system information
        - Internal paths or configuration details
        
        Args:
            service: Service information dictionary
            
        Returns:
            List[Dict[str, Any]]: Security alerts for information disclosure
        """
        alerts = []
        banner = service.get('banner', '')
        
        # Check if banner contains detailed version information
        if banner and banner != 'No banner available':
            # Look for version patterns (e.g., "1.2.3", "7.4p1")
            import re
            has_version = re.search(r'\d+\.\d+', banner)
            
            if has_version and len(banner) > 50:
                alerts.append({
                    'severity': 'LOW',
                    'title': 'Verbose Service Banner',
                    'description': (
                        f"Service on port {service['port']} exposes detailed version "
                        "information in banner. This aids attackers in identifying "
                        "specific vulnerabilities to target."
                    ),
                    'recommendation': (
                        "Configure service to minimize banner information. Remove version "
                        "numbers from banners where possible. This is a defense-in-depth "
                        "measure that makes reconnaissance more difficult."
                    ),
                    'port': service['port'],
                    'service': service['service']
                })
        
        return alerts
    
    def check_configurations(self, services: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Perform comprehensive security configuration analysis.
        
        Analyzes all detected services for security issues including:
        - Insecure protocols
        - Known vulnerable versions
        - Dangerous service exposure
        - Information disclosure
        
        Results are prioritized by severity to guide remediation efforts.
        
        Args:
            services: List of detected service dictionaries
            
        Returns:
            List[Dict[str, Any]]: Consolidated security alerts sorted by severity
        """
        logger.info(f"Analyzing security configurations for {len(services)} services")
        
        all_alerts = []
        
        for service in services:
            try:
                # Run all security checks
                alerts = []
                alerts.extend(self._check_insecure_protocols(service))
                alerts.extend(self._check_vulnerable_versions(service))
                alerts.extend(self._check_dangerous_services(service))
                alerts.extend(self._check_information_disclosure(service))
                
                all_alerts.extend(alerts)
                
            except Exception as e:
                logger.error(f"Error checking service {service.get('port')}: {e}")
        
        # Sort alerts by severity (CRITICAL > HIGH > MEDIUM > LOW)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        all_alerts.sort(key=lambda x: severity_order.get(x['severity'], 999))
        
        logger.info(
            f"Configuration analysis complete. Found {len(all_alerts)} security issues"
        )
        
        # Log summary by severity
        severity_counts = {}
        for alert in all_alerts:
            severity = alert['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in severity_counts.items():
            logger.info(f"  {severity}: {count} issue(s)")
        
        return all_alerts
