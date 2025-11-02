# VPN Hub Code Style Guide

Complete coding standards and conventions for VPN Hub development to ensure consistent, maintainable, and secure code.

## 📋 Table of Contents

- [Overview](#overview)
- [Python Style Guide](#python-style-guide)
- [Security Coding Standards](#security-coding-standards)
- [Documentation Standards](#documentation-standards)
- [Testing Standards](#testing-standards)
- [Git Standards](#git-standards)

## 🎯 Overview

This guide establishes coding standards for VPN Hub to ensure:
- **Consistency** across all code contributions
- **Security** in every aspect of development
- **Maintainability** for long-term project health
- **Readability** for effective collaboration

### **Core Principles**
1. **Security First**: Every line of code prioritizes security
2. **Clarity Over Cleverness**: Readable code is maintainable code
3. **Consistency**: Follow established patterns throughout the codebase
4. **Documentation**: Code should be self-documenting with clear comments

## 🐍 Python Style Guide

### **PEP 8 Compliance**
VPN Hub follows [PEP 8](https://pep8.org/) with specific modifications for enhanced security.

#### **Line Length**
```python
# Maximum line length: 88 characters (Black formatter default)
# This provides good readability while accommodating modern displays

# ✅ Good
def authenticate_provider(username: str, password: str) -> bool:
    return secure_authentication_handler(username, password)

# ❌ Bad - Too long
def authenticate_provider_with_enhanced_security_validation_and_comprehensive_error_handling(username: str, password: str) -> bool:
```

#### **Indentation**
```python
# Use 4 spaces per indentation level (never tabs)

# ✅ Good
def process_connection():
    if connection_available:
        if security_validated:
            establish_secure_connection()
            return True
    return False

# ❌ Bad - Inconsistent indentation
def process_connection():
  if connection_available:
      if security_validated:
    establish_secure_connection()
        return True
    return False
```

### **Naming Conventions**

#### **Variables and Functions**
```python
# snake_case for variables and functions
username = "user@example.com"
connection_status = ConnectionStatus.CONNECTED
vpn_server_list = []

def validate_user_input():
    pass

def establish_vpn_connection():
    pass
```

#### **Classes**
```python
# PascalCase for classes
class VPNProvider:
    pass

class SecurityManager:
    pass

class InputSanitizer:
    pass
```

#### **Constants**
```python
# UPPER_SNAKE_CASE for constants
MAX_RETRY_ATTEMPTS = 3
DEFAULT_TIMEOUT = 30
SECURITY_KEY_LENGTH = 256

# Security-related constants
ALLOWED_USERNAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
MAX_PASSWORD_LENGTH = 200
```

#### **Private/Protected Members**
```python
class SecurityHandler:
    def __init__(self):
        self.public_data = "visible"
        self._protected_data = "internal use"
        self.__private_key = "highly sensitive"
    
    def _internal_method(self):
        """Protected method for internal use"""
        pass
    
    def __secure_operation(self):
        """Private method for sensitive operations"""
        pass
```

### **Type Hints**
Always use type hints for better code clarity and IDE support:

```python
from typing import Dict, List, Optional, Union, Any
from pathlib import Path

def authenticate_user(
    username: str, 
    password: str, 
    provider: str = "nordvpn"
) -> bool:
    """Authenticate user with VPN provider."""
    pass

def get_server_list(
    provider: str, 
    country_filter: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve filtered server list."""
    pass

class VPNConnection:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
    
    def connect(self, server: str) -> bool:
        pass
```

### **Imports Organization**
```python
# 1. Standard library imports
import os
import sys
import asyncio
from pathlib import Path
from typing import Dict, List, Optional

# 2. Third-party imports
import aiohttp
from PyQt5.QtWidgets import QMainWindow
from cryptography.fernet import Fernet

# 3. Local application imports
from .security import InputSanitizer, SecurityManager
from .core import VPNInterface, ConnectionManager
from ..providers import NordVPNProvider
```

## 🔒 Security Coding Standards

### **Input Validation**
```python
# ✅ Always validate and sanitize user inputs
from src.security.input_sanitizer import InputSanitizer

def process_username(raw_username: str) -> str:
    """Process and validate username input."""
    try:
        # Always sanitize first
        sanitized = InputSanitizer.sanitize_username(raw_username)
        
        # Additional validation
        if len(sanitized) > MAX_USERNAME_LENGTH:
            raise ValidationError("Username too long")
        
        return sanitized
    except SecurityException as e:
        logger.error(f"Username validation failed: {e}")
        raise

# ❌ Never trust raw user input
def bad_username_handler(username: str) -> str:
    return username  # No validation - security risk!
```

### **Credential Handling**
```python
# ✅ Secure credential handling
def authenticate_safely(username: str, password: str):
    """Authenticate with secure credential handling."""
    try:
        # Never log sensitive data
        logger.info(f"Authentication attempt for user: {username}")
        
        # Use environment variables for credentials
        env_vars = {
            "VPN_USERNAME": username,
            "VPN_PASSWORD": password  # Passed securely, never in logs
        }
        
        # Execute with secure command executor
        result = await secure_executor.execute_command(
            ["vpn", "login"], 
            env_vars=env_vars
        )
        
        return result.returncode == 0
    
    except Exception as e:
        # Never expose sensitive data in error messages
        logger.error("Authentication failed")
        raise AuthenticationError("Authentication failed")

# ❌ Insecure credential handling
def bad_authentication(username: str, password: str):
    # Never do this - logs sensitive data
    logger.info(f"Logging in {username} with password {password}")
    
    # Never pass credentials in command line
    subprocess.run(["vpn", "login", username, password])
```

### **Error Handling**
```python
# ✅ Secure error handling
def secure_operation():
    """Example of secure error handling."""
    try:
        result = perform_sensitive_operation()
        return result
    
    except AuthenticationError:
        # Log detailed error internally
        logger.error("Authentication failed for secure operation", exc_info=True)
        # Return generic error to user
        raise AuthenticationError("Authentication failed")
    
    except Exception as e:
        # Log unexpected errors without exposing internals
        logger.error(f"Unexpected error in secure_operation", exc_info=True)
        # Don't expose internal error details
        raise SystemError("Operation failed")

# ❌ Insecure error handling
def bad_error_handling():
    try:
        secret_operation()
    except Exception as e:
        # Never expose internal details
        return f"Error: {str(e)}"  # Potential information disclosure
```

### **Logging Standards**
```python
import logging

# ✅ Secure logging practices
logger = logging.getLogger(__name__)

def secure_logging_example(username: str, operation: str):
    """Example of secure logging."""
    # Log non-sensitive information
    logger.info(f"User {username} attempted {operation}")
    
    # Never log sensitive data
    # logger.info(f"Password: {password}")  # NEVER DO THIS
    
    # Use appropriate log levels
    logger.debug("Debug information for development")
    logger.info("General information")
    logger.warning("Warning about potential issues")
    logger.error("Error occurred", exc_info=True)
    
    # Sanitize any user input before logging
    sanitized_input = InputSanitizer.sanitize_for_logging(user_input)
    logger.info(f"Processing input: {sanitized_input}")
```

## 📚 Documentation Standards

### **Docstring Format**
Use Google-style docstrings for all functions, classes, and modules:

```python
def authenticate_provider(
    username: str, 
    password: str, 
    provider: str = "nordvpn",
    timeout: float = 30.0
) -> bool:
    """
    Authenticate with a VPN provider using secure credential handling.
    
    This function safely authenticates with VPN providers while ensuring
    all inputs are properly sanitized and validated for security.
    
    Args:
        username: User's VPN account username or email
        password: User's VPN account password  
        provider: VPN provider name (default: "nordvpn")
        timeout: Authentication timeout in seconds (default: 30.0)
        
    Returns:
        bool: True if authentication successful, False otherwise
        
    Raises:
        SecurityException: If input validation fails
        AuthenticationError: If provider authentication fails
        ConnectionError: If network connection fails
        
    Example:
        >>> success = authenticate_provider(
        ...     "user@example.com", 
        ...     "secure_password", 
        ...     "nordvpn"
        ... )
        >>> if success:
        ...     print("Authentication successful")
    
    Security:
        - All inputs are sanitized using InputSanitizer
        - Passwords are handled securely and never logged
        - Credentials are encrypted before storage
        
    Note:
        This function requires administrator privileges on some systems
        for full network configuration access.
    """
    # Implementation here
    pass
```

### **Class Documentation**
```python
class SecurityManager:
    """
    Manages comprehensive security features for VPN Hub.
    
    The SecurityManager provides enterprise-grade security including
    kill switches, DNS leak protection, and network monitoring.
    
    Attributes:
        is_kill_switch_active: Boolean indicating kill switch status
        safe_ips: List of allowed IP addresses during kill switch
        
    Example:
        >>> manager = SecurityManager()
        >>> await manager.enable_kill_switch(["192.168.1.1"])
        >>> print(manager.is_kill_switch_active)
        True
    """
    
    def __init__(self):
        """Initialize SecurityManager with default settings."""
        self.is_kill_switch_active = False
        self.safe_ips = []
```

### **Module Documentation**
```python
"""
VPN Provider Interface Module

This module provides the abstract base class and common interfaces
for all VPN provider implementations in VPN Hub.

Classes:
    VPNProviderInterface: Abstract base class for VPN providers
    ServerInfo: Data class for VPN server information
    ConnectionInfo: Data class for connection details
    
Security Considerations:
    - All provider implementations must use secure credential handling
    - Input validation is required for all external data
    - Network communications must use certificate pinning
    
Example:
    >>> from providers.nordvpn import NordVPNProvider
    >>> provider = NordVPNProvider(config)
    >>> await provider.authenticate(username, password)
"""
```

### **Inline Comments**
```python
def complex_security_operation():
    """Perform complex security validation."""
    # Step 1: Validate user permissions
    if not self._check_user_permissions():
        raise PermissionError("Insufficient privileges")
    
    # Step 2: Sanitize all inputs to prevent injection attacks
    sanitized_data = self._sanitize_inputs(raw_data)
    
    # Step 3: Apply encryption with AES-256
    # Using GCM mode for authenticated encryption
    encrypted_data = self._encrypt_with_aes_gcm(sanitized_data)
    
    # Step 4: Verify integrity with HMAC
    signature = self._generate_hmac_signature(encrypted_data)
    
    return encrypted_data, signature
```

## 🧪 Testing Standards

### **Test Organization**
```python
# test_security_manager.py
import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from src.security.security_manager import SecurityManager
from src.exceptions import SecurityException

class TestSecurityManager:
    """Comprehensive test suite for SecurityManager."""
    
    @pytest.fixture
    def security_manager(self):
        """Create SecurityManager instance for testing."""
        return SecurityManager()
    
    @pytest.fixture
    def mock_network_interface(self):
        """Mock network interface for testing."""
        return Mock()
    
    @pytest.mark.asyncio
    async def test_enable_kill_switch_success(self, security_manager):
        """Test successful kill switch activation."""
        # Arrange
        safe_ips = ["192.168.1.1", "10.0.0.1"]
        
        # Act
        result = await security_manager.enable_kill_switch(safe_ips)
        
        # Assert
        assert result is True
        assert security_manager.is_kill_switch_active is True
        assert security_manager.safe_ips == safe_ips
    
    @pytest.mark.asyncio
    async def test_enable_kill_switch_invalid_ip(self, security_manager):
        """Test kill switch with invalid IP address."""
        # Arrange
        invalid_ips = ["invalid.ip.address"]
        
        # Act & Assert
        with pytest.raises(SecurityException):
            await security_manager.enable_kill_switch(invalid_ips)
```

### **Test Naming Conventions**
```python
# Test method naming: test_[method]_[scenario]_[expected_result]
def test_authenticate_valid_credentials_returns_true():
    """Test authentication with valid credentials returns True."""
    pass

def test_authenticate_invalid_credentials_returns_false():
    """Test authentication with invalid credentials returns False."""
    pass

def test_sanitize_malicious_input_raises_security_exception():
    """Test sanitizer raises SecurityException for malicious input."""
    pass
```

## 📝 Git Standards

### **Commit Message Format**
```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

#### **Types**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code formatting (no logic changes)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Maintenance tasks
- `security`: Security-related changes

#### **Examples**
```bash
feat(providers): add CyberGhost VPN support

- Implement CyberGhost provider class
- Add authentication methods
- Include server list functionality
- Add comprehensive test coverage

Closes #123

fix(security): resolve credential encryption vulnerability

- Update encryption algorithm to AES-256-GCM
- Add proper key derivation using PBKDF2
- Implement secure key storage

Security impact: Addresses CVE-2024-12345

docs(api): update provider integration examples

- Add NordVPN integration example
- Update authentication flow documentation
- Fix typos in security guidelines

test(security): add comprehensive input sanitization tests

- Test SQL injection prevention
- Test command injection prevention  
- Test XSS prevention
- Add performance benchmarks
```

### **Branch Naming**
```bash
# Feature branches
feature/add-cyberghost-support
feature/enhanced-security-monitoring

# Bug fix branches
fix/authentication-timeout-issue
fix/memory-leak-in-connection-manager

# Documentation branches
docs/update-api-reference
docs/add-installation-guide

# Security branches
security/fix-credential-exposure
security/update-encryption-standards
```

## 🛠️ Code Quality Tools

### **Required Tools**
```bash
# Formatting
black                 # Code formatting
isort                # Import sorting

# Linting
flake8               # Style guide enforcement
mypy                 # Static type checking

# Security
bandit               # Security issue detection
safety               # Dependency vulnerability scanning

# Testing
pytest               # Testing framework
pytest-cov          # Coverage reporting
pytest-asyncio      # Async testing support
```

### **Configuration Files**

#### **pyproject.toml**
```toml
[tool.black]
line-length = 88
target-version = ['py38', 'py39', 'py310', 'py311']
include = '\.pyi?$'
extend-exclude = '''
/(
  # directories
  \.eggs
  | \.git
  | \.hg
  | \.mypy_cache
  | \.tox
  | \.venv
  | _build
  | buck-out
  | build
  | dist
)/
'''

[tool.isort]
profile = "black"
multi_line_output = 3
line_length = 88
known_third_party = ["aiohttp", "PyQt5", "cryptography"]
known_first_party = ["src"]

[tool.mypy]
python_version = "3.11"
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true
no_implicit_optional = true
warn_redundant_casts = true
warn_unused_ignores = true
warn_no_return = true
warn_unreachable = true
strict_equality = true
```

#### **.flake8**
```ini
[flake8]
max-line-length = 88
extend-ignore = E203, W503
exclude = 
    .git,
    __pycache__,
    .venv,
    .eggs,
    *.egg,
    build,
    dist
per-file-ignores =
    __init__.py:F401
```

### **Pre-commit Configuration**
```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.3.0
    hooks:
      - id: black
        language_version: python3.11

  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort

  - repo: https://github.com/pycqa/flake8
    rev: 6.0.0
    hooks:
      - id: flake8

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.3.0
    hooks:
      - id: mypy

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-r', 'src/']
```

## 📊 Code Review Checklist

### **Security Review**
- [ ] All user inputs are validated and sanitized
- [ ] No hardcoded credentials or sensitive data
- [ ] Proper error handling without information disclosure
- [ ] Secure credential handling (environment variables)
- [ ] No sensitive data in logs
- [ ] SQL/Command injection prevention implemented

### **Code Quality Review**
- [ ] Follows naming conventions
- [ ] Proper type hints used
- [ ] Comprehensive docstrings
- [ ] Appropriate error handling
- [ ] No code duplication
- [ ] Performance considerations addressed

### **Testing Review**
- [ ] Adequate test coverage (>85%)
- [ ] Unit tests for all public methods
- [ ] Security test cases included
- [ ] Edge cases covered
- [ ] Async code properly tested
- [ ] Mock objects used appropriately

### **Documentation Review**
- [ ] Code is self-documenting
- [ ] Complex logic explained with comments
- [ ] API documentation updated
- [ ] Security considerations documented
- [ ] Examples provided where helpful

---

**Code Style Guide Version:** 2.0  
**Last Updated:** November 1, 2025  
**Maintained by:** FNBubbles420 Org