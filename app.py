"""
Security Scanner - Flask Application Entry Point

This module provides the web interface for a passive security scanner.
Designed for authorized security audits only.

Author: Professional Security Portfolio Project
License: MIT
"""

from flask import Flask, render_template, request, jsonify
from typing import Dict, Any
import logging
from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from scanner.config_checks import ConfigurationChecker

# Configure logging for security audit trail
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-change-in-production'


@app.route('/')
def index() -> str:
    """
    Render the main scanner interface.
    
    Returns:
        str: Rendered HTML template for the scanner form
    """
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan() -> Dict[str, Any]:
    """
    Handle scan requests from the web interface.
    
    This endpoint processes scan parameters, executes the security scan,
    and returns comprehensive results. All scans are logged for audit purposes.
    
    Security considerations:
    - Input validation prevents malicious targets
    - Scans are strictly non-exploitative
    - Rate limiting recommended for production
    
    Returns:
        Dict[str, Any]: JSON response containing scan results or error details
    """
    try:
        # Extract and validate scan parameters
        target = request.json.get('target', '').strip()
        port_range_start = request.json.get('port_start', 1)
        port_range_end = request.json.get('port_end', 1000)
        
        # Input validation
        if not target:
            return jsonify({
                'success': False,
                'error': 'Target IP or hostname is required'
            }), 400
        
        # Validate port range
        if not (1 <= port_range_start <= 65535 and 1 <= port_range_end <= 65535):
            return jsonify({
                'success': False,
                'error': 'Port range must be between 1 and 65535'
            }), 400
        
        if port_range_start > port_range_end:
            return jsonify({
                'success': False,
                'error': 'Start port must be less than or equal to end port'
            }), 400
        
        # Log scan initiation for audit trail
        logger.info(f"Initiating scan on target: {target}, ports: {port_range_start}-{port_range_end}")
        
        # Phase 1: Port scanning
        port_scanner = PortScanner(target, port_range_start, port_range_end)
        open_ports = port_scanner.scan()
        
        if not open_ports:
            return jsonify({
                'success': True,
                'target': target,
                'open_ports': [],
                'services': [],
                'security_alerts': [],
                'message': 'No open ports found in the specified range'
            })
        
        # Phase 2: Service detection
        service_detector = ServiceDetector(target)
        services = service_detector.detect_services(open_ports)
        
        # Phase 3: Configuration security checks
        config_checker = ConfigurationChecker(target)
        security_alerts = config_checker.check_configurations(services)
        
        # Compile comprehensive results
        results = {
            'success': True,
            'target': target,
            'open_ports': open_ports,
            'services': services,
            'security_alerts': security_alerts
        }
        
        logger.info(f"Scan completed for {target}. Found {len(open_ports)} open ports")
        
        return jsonify(results)
        
    except ValueError as ve:
        logger.error(f"Validation error during scan: {str(ve)}")
        return jsonify({
            'success': False,
            'error': f'Invalid input: {str(ve)}'
        }), 400
        
    except ConnectionError as ce:
        logger.error(f"Connection error during scan: {str(ce)}")
        return jsonify({
            'success': False,
            'error': f'Unable to connect to target: {str(ce)}'
        }), 500
        
    except Exception as e:
        logger.error(f"Unexpected error during scan: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': 'An unexpected error occurred. Please check logs.'
        }), 500


@app.errorhandler(404)
def not_found(error) -> tuple:
    """Handle 404 errors gracefully."""
    return jsonify({'success': False, 'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error) -> tuple:
    """Handle 500 errors gracefully."""
    logger.error(f"Internal server error: {error}")
    return jsonify({'success': False, 'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Development server configuration
    # WARNING: Do not use in production without proper security hardening
    logger.info("Starting Security Scanner web interface on http://localhost:5000")
    logger.warning("This tool should only be used on systems you own or have explicit permission to scan")
    
    app.run(
        host='127.0.0.1',  # Localhost only for security
        port=5000,
        debug=True  # Disable in production
    )
