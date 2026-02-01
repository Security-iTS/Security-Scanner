"""
Security Scanner - Production Configuration Example

This file demonstrates production-ready configuration settings.
Copy to config.py and customize for your deployment.

SECURITY NOTES:
- Change SECRET_KEY to a random value
- Enable HTTPS in production
- Configure rate limiting
- Set up authentication if multi-user
- Use environment variables for sensitive data
"""

import os
from datetime import timedelta


class Config:
    """Base configuration class."""
    
    # Flask Configuration
    # CRITICAL: Change this to a random secret key in production
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-CHANGE-THIS-IN-PRODUCTION'
    
    # Server Configuration
    HOST = os.environ.get('FLASK_HOST') or '127.0.0.1'  # Localhost only by default
    PORT = int(os.environ.get('FLASK_PORT') or 5000)
    DEBUG = False  # Always False in production
    
    # Scanning Configuration
    DEFAULT_PORT_START = 1
    DEFAULT_PORT_END = 1000
    MAX_PORT_RANGE = 10000  # Limit to prevent excessive scanning
    
    SCAN_TIMEOUT = 1.0  # Socket timeout in seconds
    SERVICE_TIMEOUT = 2.0  # Service detection timeout
    MAX_CONCURRENT_SCANS = 50  # Thread pool size
    
    # Rate Limiting (recommended for production)
    # Requires Flask-Limiter: pip install Flask-Limiter
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URL = 'memory://'
    RATELIMIT_DEFAULT = '10 per hour'  # 10 scans per hour per IP
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL') or 'INFO'
    LOG_FILE = os.environ.get('LOG_FILE') or 'security_scanner.log'
    LOG_MAX_BYTES = 10485760  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }
    
    # Session Configuration
    SESSION_COOKIE_SECURE = True  # HTTPS only
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)


class DevelopmentConfig(Config):
    """Development environment configuration."""
    
    DEBUG = True
    HOST = '127.0.0.1'
    SESSION_COOKIE_SECURE = False  # Allow HTTP in dev


class ProductionConfig(Config):
    """Production environment configuration."""
    
    DEBUG = False
    RATELIMIT_ENABLED = True
    
    # Production should always use HTTPS
    SESSION_COOKIE_SECURE = True
    
    # Stricter timeouts in production
    SCAN_TIMEOUT = 0.5
    MAX_CONCURRENT_SCANS = 30


class TestingConfig(Config):
    """Testing environment configuration."""
    
    TESTING = True
    WTF_CSRF_ENABLED = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config():
    """
    Get configuration based on environment.
    
    Returns:
        Config: Configuration object for current environment
    """
    env = os.environ.get('FLASK_ENV') or 'development'
    return config.get(env, config['default'])
