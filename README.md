# 🔒 Security Scanner

A professional-grade passive network security assessment tool with web interface. Designed for authorized security audits and penetration testing engagements.

## ⚠️ Legal Notice

**IMPORTANT**: This tool is designed for **authorized security assessments only**. 

- ✅ Use only on systems you own
- ✅ Use only with explicit written permission from system owners
- ❌ Unauthorized scanning may be illegal under computer fraud and abuse laws
- ❌ This tool is for defensive security purposes only

The author assumes no liability for misuse of this software.

## 🎯 Features

### Passive Reconnaissance
- **Non-intrusive TCP port scanning** - Standard socket connections, no SYN floods
- **Service fingerprinting** - Banner grabbing for version detection
- **Configuration analysis** - Identifies common security misconfigurations

### Security Checks
- ✓ Insecure protocol detection (Telnet, FTP, unencrypted HTTP)
- ✓ Vulnerable software version identification
- ✓ Dangerous service exposure (databases, RDP, SMB)
- ✓ Information disclosure analysis
- ✓ Severity-based risk prioritization

### User Experience
- 🌐 Clean, responsive web interface
- 📊 Real-time scan progress indication
- 🎨 Color-coded severity alerts (CRITICAL, HIGH, MEDIUM, LOW)
- 📝 Detailed remediation recommendations
- 🔍 CVE references for known vulnerabilities

## 🏗️ Architecture

```
security_scanner/
├── app.py                      # Flask application entry point
├── scanner/                    # Core scanning modules
│   ├── __init__.py            # Package initialization
│   ├── port_scanner.py        # TCP port scanning logic
│   ├── service_detector.py    # Service fingerprinting
│   └── config_checks.py       # Security configuration analysis
├── templates/                  # HTML templates
│   └── index.html             # Main web interface
├── static/                     # Static assets
│   └── style.css              # Custom styling
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

### Component Overview

**app.py**: Flask web application providing REST API and UI
- Input validation and sanitization
- Error handling and logging
- Audit trail generation

**port_scanner.py**: Concurrent TCP port scanner
- Thread pool for performance
- Configurable timeout and port ranges
- Graceful error handling

**service_detector.py**: Service fingerprinting engine
- Banner grabbing (read-only)
- Regex-based version parsing
- Common port mappings

**config_checks.py**: Security analysis module
- Vulnerability database (simplified CVE references)
- Best practice validation
- Risk-based prioritization

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Network access to target systems

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner
```

2. **Create virtual environment** (recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Starting the Application

```bash
python app.py
```

The web interface will be available at: **http://localhost:5000**

### Performing a Scan

1. Open http://localhost:5000 in your browser
2. Enter target IP address or hostname (you must have permission to scan)
3. Specify port range (default: 1-1000)
4. Click "Start Scan"
5. Review results and security alerts

### Command-Line Usage (Alternative)

For programmatic use, import the modules directly:

```python
from scanner import PortScanner, ServiceDetector, ConfigurationChecker

# Initialize scanner
scanner = PortScanner(target="192.168.1.1", port_start=1, port_end=1000)

# Scan for open ports
open_ports = scanner.scan()

# Detect services
detector = ServiceDetector(target="192.168.1.1")
services = detector.detect_services(open_ports)

# Check configurations
checker = ConfigurationChecker(target="192.168.1.1")
alerts = checker.check_configurations(services)

# Process results
for alert in alerts:
    print(f"{alert['severity']}: {alert['title']}")
```

## 🔐 Security Considerations

### What This Tool Does
- ✅ Passive TCP connection attempts
- ✅ Read service banners (no data sent)
- ✅ Analyze configurations against best practices

### What This Tool Does NOT Do
- ❌ Exploit vulnerabilities
- ❌ Brute force authentication
- ❌ Perform denial of service attacks
- ❌ Modify target systems
- ❌ Extract sensitive data

### Best Practices for Use
1. **Always obtain written authorization** before scanning
2. **Document all scans** in engagement notes
3. **Respect rate limits** to avoid service disruption
4. **Use VPN/secure connection** when scanning remote systems
5. **Review and verify findings** before reporting

## 🛡️ Ethical Considerations

This tool is designed for **defensive security** purposes:

- Security audits and assessments
- Compliance testing (PCI-DSS, HIPAA, etc.)
- Vulnerability management programs
- Red team/blue team exercises
- Educational and research purposes

**Never use this tool for:**
- Unauthorized access attempts
- Malicious reconnaissance
- Network disruption
- Any illegal activities

## 📊 Understanding Results

### Severity Levels

- **CRITICAL** 🔴: Immediate action required (e.g., Telnet exposed to internet)
- **HIGH** 🟠: Significant risk (e.g., outdated software with known exploits)
- **MEDIUM** 🟡: Security improvement recommended (e.g., HTTP instead of HTTPS)
- **LOW** ⚪: Minor enhancement (e.g., verbose service banners)

### Common Findings

**Insecure Protocols**
- Telnet (port 23): Cleartext credentials
- FTP (port 21): Unencrypted file transfer
- HTTP (port 80): Unencrypted web traffic

**Dangerous Exposures**
- Database ports (3306, 5432, 27017): Should not be internet-facing
- RDP (3389): Frequent brute-force target
- SMB (445): Historical attack vector (WannaCry, NotPetya)

**Version-Specific Vulnerabilities**
- OpenSSH < 7.4: User enumeration (CVE-2018-15473)
- Apache 2.4.49: Path traversal RCE (CVE-2021-41773)
- Various end-of-life software with unpatched vulnerabilities

## 🔧 Configuration

### Adjusting Scan Parameters

Edit `app.py` or modify web form defaults:

```python
# Default timeout for port scanning
timeout = 1.0  # seconds

# Maximum concurrent threads
max_workers = 50

# Service detection timeout
service_timeout = 2.0  # seconds
```

### Production Deployment

For production use:

1. **Disable debug mode** in `app.py`:
```python
app.run(debug=False)
```

2. **Use production WSGI server** (gunicorn):
```bash
pip install gunicorn
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

3. **Implement rate limiting** to prevent abuse
4. **Add authentication** for multi-user deployments
5. **Enable HTTPS** with valid SSL certificate
6. **Configure logging** to secure audit log location

## 🧪 Testing

Test the scanner on controlled environments:

```bash
# Test on localhost (safe)
Target: 127.0.0.1
Ports: 1-1000

# Test on Docker container (recommended for practice)
docker run -d -p 21:21 -p 22:22 -p 80:80 metasploitable3
Target: localhost
```

**Never test on production systems without approval.**

## 📝 Logging

All scans are logged for audit purposes:

```
2024-02-01 10:30:15 - Initiating scan on target: 192.168.1.1, ports: 1-1000
2024-02-01 10:30:45 - Scan complete. Found 5 open ports
2024-02-01 10:30:48 - Configuration analysis complete. Found 3 security issues
```

Review logs in console output or configure file-based logging.

## 🤝 Contributing

This is a portfolio project demonstrating security engineering skills. Contributions welcome:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -m 'Add security check for X'`)
4. Push to branch (`git push origin feature/enhancement`)
5. Open Pull Request

## 📚 Resources

**Security Best Practices:**
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks/

**CVE Databases:**
- National Vulnerability Database: https://nvd.nist.gov/
- CVE Details: https://www.cvedetails.com/

**Legal Compliance:**
- Computer Fraud and Abuse Act (CFAA)
- General Data Protection Regulation (GDPR)
- Your local laws and regulations

## 📄 License

MIT License - See LICENSE file for details

**Disclaimer**: This software is provided "as is" without warranty of any kind. The author is not responsible for any damages or legal issues arising from use or misuse of this tool.

## 👤 Author

Created as a professional portfolio project demonstrating:
- Network security expertise
- Secure coding practices
- Web application development
- Ethical hacking methodology
- Professional documentation

## 🔗 Links

- GitHub: [Your GitHub Profile]
- LinkedIn: [Your LinkedIn Profile]
- Portfolio: [Your Portfolio Website]

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally.
