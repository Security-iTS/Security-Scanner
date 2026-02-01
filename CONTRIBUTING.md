# Contributing to Security Scanner

Thank you for your interest in contributing to this security assessment tool! This document provides guidelines for contributing code, reporting issues, and suggesting improvements.

## 🎯 Project Goals

This project aims to:
- Provide a **professional-grade** passive security scanner
- Demonstrate **best practices** in secure coding
- Serve as a **portfolio piece** for security professionals
- Educate on **ethical security assessment** methodologies

## 🤝 How to Contribute

### Reporting Bugs

If you discover a bug:

1. **Check existing issues** to avoid duplicates
2. **Create a new issue** with:
   - Clear, descriptive title
   - Steps to reproduce
   - Expected vs. actual behavior
   - Environment details (OS, Python version)
   - Relevant logs or screenshots

### Suggesting Features

For feature requests:

1. **Open an issue** labeled "enhancement"
2. **Explain the use case** and benefits
3. **Consider security implications**
4. **Propose implementation** if possible

### Code Contributions

#### Getting Started

1. **Fork the repository**
2. **Clone your fork**:
   ```bash
   git clone https://github.com/Security-iTS/security-scanner.git
   cd security-scanner
   ```
3. **Create a branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

#### Development Guidelines

**Code Style**
- Follow **PEP 8** conventions
- Use **type hints** for function parameters and returns
- Write **descriptive variable names**
- Keep functions **focused and single-purpose**

**Documentation**
- Add **docstrings** to all functions/classes
- Include **security considerations** in comments
- Update **README.md** if adding features
- Provide **usage examples** for new functionality

**Testing**
- Write **unit tests** for new code
- Ensure **existing tests pass**
- Test on **multiple Python versions** (3.8+)
- Include **integration tests** for workflows

**Security**
- Never add **exploitation capabilities**
- Avoid **dependencies with known vulnerabilities**
- Consider **input validation** and **error handling**
- Document **security implications** of changes

#### Code Review Checklist

Before submitting:

- [ ] Code follows PEP 8 style guide
- [ ] All functions have docstrings
- [ ] Type hints are used consistently
- [ ] Security implications are documented
- [ ] Tests are included and passing
- [ ] README is updated if needed
- [ ] No hardcoded credentials or sensitive data
- [ ] Error handling is comprehensive

#### Submitting Pull Requests

1. **Push your changes**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open a Pull Request** with:
   - Clear description of changes
   - Reference to related issues
   - Screenshots/examples if UI changes
   - Test results

3. **Respond to feedback** promptly

4. **Ensure CI passes** (if configured)

## 📝 Coding Standards

### Python Style

```python
# Good: Clear, typed, documented
def scan_port(target: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a TCP port is open on target system.
    
    Args:
        target: IP address or hostname
        port: Port number (1-65535)
        timeout: Connection timeout in seconds
        
    Returns:
        bool: True if port is open, False otherwise
        
    Security Note:
        Uses standard TCP connect, no SYN flooding
    """
    # Implementation
    pass

# Bad: No types, no docs, unclear
def check(t, p):
    # what does this do?
    pass
```

### Security-First Mindset

**DO:**
- ✅ Validate all user inputs
- ✅ Use timeout on network operations
- ✅ Log security-relevant actions
- ✅ Handle errors gracefully
- ✅ Document security implications

**DON'T:**
- ❌ Add exploitation features
- ❌ Include offensive security tools
- ❌ Hardcode credentials
- ❌ Ignore rate limiting
- ❌ Bypass authentication

## 🧪 Testing

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
python -m pytest test_scanner.py -v

# Run with coverage
python -m pytest test_scanner.py --cov=scanner --cov-report=html
```

### Writing Tests

```python
import unittest
from scanner.port_scanner import PortScanner

class TestNewFeature(unittest.TestCase):
    """Test cases for new feature."""
    
    def test_valid_input(self):
        """Test with valid inputs."""
        # Arrange
        scanner = PortScanner("127.0.0.1", 1, 100)
        
        # Act
        result = scanner.some_new_method()
        
        # Assert
        self.assertIsNotNone(result)
```

## 📋 Enhancement Ideas

Areas where contributions are welcome:

### Core Functionality
- **IPv6 support** for modern networks
- **UDP port scanning** capabilities
- **OS fingerprinting** (passive techniques)
- **SSL/TLS analysis** for HTTPS services
- **DNS enumeration** features

### Security Checks
- **Additional CVE database** integration
- **CIS Benchmark** compliance checks
- **OWASP Top 10** vulnerability checks
- **Weak cipher detection** for SSL/TLS
- **Default credential** warnings

### User Experience
- **Progress bar** for long scans
- **Export results** (PDF, JSON, CSV)
- **Scan history** and comparison
- **Dark mode** UI theme
- **Mobile-responsive** improvements

### DevOps
- **Docker container** for easy deployment
- **CI/CD pipeline** configuration
- **Automated testing** workflow
- **Code quality** tools (Black, Pylint)

## 🔒 Security Disclosure

If you discover a security vulnerability:

1. **Do NOT** open a public issue
2. **Email** the maintainer directly (provide contact)
3. **Allow 90 days** for fix before disclosure
4. **Coordinate** on responsible disclosure timeline

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Recognition

Contributors will be:
- Listed in **CONTRIBUTORS.md**
- Mentioned in **release notes**
- Credited in **documentation**

## 💬 Communication

- **Issues**: For bugs and feature requests
- **Pull Requests**: For code contributions
- **Discussions**: For questions and ideas (if enabled)

## ✨ Code of Conduct

### Our Standards

**Positive behaviors:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community

**Unacceptable behaviors:**
- Trolling, insulting/derogatory comments
- Public or private harassment
- Publishing others' private information
- Advocating for malicious use of security tools

### Enforcement

Violations may result in:
1. Warning
2. Temporary ban
3. Permanent ban

## 🎓 Learning Resources

For contributors new to security:

- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **Python Security Best Practices**: https://python.readthedocs.io/en/stable/library/security_warnings.html
- **Ethical Hacking**: https://www.offensive-security.com/
- **CVE Database**: https://cve.mitre.org/

---

**Thank you for helping make this tool better while maintaining the highest ethical and security standards!**
