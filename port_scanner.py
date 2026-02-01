"""
Security Scanner - Port Scanner Module

This module implements a passive TCP port scanner using socket connections.
It identifies open ports on a target system without exploiting vulnerabilities.

Ethical Usage:
- Only scan systems you own or have explicit written permission to test
- Respect rate limits to avoid disrupting services
- Log all scanning activity for audit purposes

Technical Approach:
- TCP SYN connection attempts (no SYN flood)
- Configurable timeout to balance speed and accuracy
- Graceful error handling for unreachable hosts
"""

import socket
import logging
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class PortScanner:
    """
    Non-intrusive TCP port scanner for security audits.
    
    This scanner uses standard socket connections to identify open ports.
    It does not attempt exploitation, brute force, or denial of service.
    
    Attributes:
        target (str): IP address or hostname to scan
        port_start (int): Starting port number (1-65535)
        port_end (int): Ending port number (1-65535)
        timeout (float): Socket connection timeout in seconds
        max_workers (int): Maximum concurrent threads for scanning
    """
    
    def __init__(
        self,
        target: str,
        port_start: int = 1,
        port_end: int = 1000,
        timeout: float = 1.0,
        max_workers: int = 50
    ):
        """
        Initialize the port scanner with target parameters.
        
        Args:
            target: IP address or hostname to scan
            port_start: First port to scan (default: 1)
            port_end: Last port to scan (default: 1000)
            timeout: Connection timeout in seconds (default: 1.0)
            max_workers: Maximum concurrent scan threads (default: 50)
            
        Raises:
            ValueError: If port range or timeout is invalid
        """
        self.target = target
        self.port_start = port_start
        self.port_end = port_end
        self.timeout = timeout
        self.max_workers = max_workers
        
        # Validate inputs
        self._validate_parameters()
        
    def _validate_parameters(self) -> None:
        """
        Validate scanner configuration parameters.
        
        Ensures port range and timeout are within acceptable bounds
        to prevent misuse and ensure reliable results.
        
        Raises:
            ValueError: If any parameter is invalid
        """
        if not (1 <= self.port_start <= 65535):
            raise ValueError("Start port must be between 1 and 65535")
        
        if not (1 <= self.port_end <= 65535):
            raise ValueError("End port must be between 1 and 65535")
        
        if self.port_start > self.port_end:
            raise ValueError("Start port must be less than or equal to end port")
        
        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")
        
        # Warn if scanning too many ports (potential network impact)
        port_count = self.port_end - self.port_start + 1
        if port_count > 10000:
            logger.warning(
                f"Scanning {port_count} ports may take significant time and network resources"
            )
    
    def _check_port(self, port: int) -> bool:
        """
        Check if a single TCP port is open using socket connection.
        
        This method attempts a standard TCP connection to determine port state.
        It does not send any application-layer data or attempt exploitation.
        
        Connection states:
        - Open: Connection succeeds
        - Closed: Connection refused
        - Filtered: Connection timeout (firewall may be blocking)
        
        Args:
            port: Port number to check
            
        Returns:
            bool: True if port is open, False otherwise
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            # Attempt TCP connection
            result = sock.connect_ex((self.target, port))
            
            # Result code 0 indicates successful connection (open port)
            if result == 0:
                logger.debug(f"Port {port} is open on {self.target}")
                return True
            else:
                return False
                
        except socket.gaierror:
            # DNS resolution failed
            logger.error(f"Could not resolve hostname: {self.target}")
            raise ConnectionError(f"Unable to resolve hostname: {self.target}")
            
        except socket.timeout:
            # Connection timed out (likely filtered by firewall)
            logger.debug(f"Port {port} timed out (possibly filtered)")
            return False
            
        except socket.error as e:
            # Other socket errors (network unreachable, etc.)
            logger.debug(f"Socket error on port {port}: {e}")
            return False
            
        finally:
            sock.close()
    
    def scan(self) -> List[int]:
        """
        Execute concurrent port scan across specified range.
        
        Uses thread pool for parallel scanning to improve performance
        while respecting system resources. The scan is purely passive
        and does not attempt to exploit discovered services.
        
        Performance considerations:
        - Thread pool prevents resource exhaustion
        - Timeout prevents hanging on filtered ports
        - Concurrent execution improves scan speed
        
        Returns:
            List[int]: Sorted list of open port numbers
            
        Raises:
            ConnectionError: If unable to reach target
        """
        logger.info(
            f"Starting port scan on {self.target} "
            f"(ports {self.port_start}-{self.port_end})"
        )
        
        open_ports = []
        
        # Use thread pool for concurrent scanning
        # Max workers limited to prevent network flooding
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit scan tasks for all ports in range
            future_to_port = {
                executor.submit(self._check_port, port): port
                for port in range(self.port_start, self.port_end + 1)
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                
                try:
                    if future.result():
                        open_ports.append(port)
                        
                except Exception as e:
                    logger.error(f"Error scanning port {port}: {e}")
        
        # Sort results for consistent output
        open_ports.sort()
        
        logger.info(f"Scan complete. Found {len(open_ports)} open ports")
        
        return open_ports
