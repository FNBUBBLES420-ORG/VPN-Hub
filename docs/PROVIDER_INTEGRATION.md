# VPN Hub Provider Integration Guide

Complete guide for integrating new VPN providers into VPN Hub enterprise-grade secure VPN manager.

## 📋 Table of Contents

- [Provider Architecture](#provider-architecture)
- [Base Provider Interface](#base-provider-interface)
- [Implementation Guide](#implementation-guide)
- [Security Requirements](#security-requirements)
- [Testing Integration](#testing-integration)
- [Registration Process](#registration-process)

## 🏗️ Provider Architecture

VPN Hub uses a plugin-based architecture for VPN providers, allowing easy integration of new services while maintaining security and consistency.

### **Architecture Overview**

```
VPN Hub Core
├── Provider Factory
│   ├── Provider Registry
│   ├── Provider Loader
│   └── Provider Validator
├── Base Provider Interface
│   ├── Authentication Methods
│   ├── Connection Management
│   ├── Server Discovery
│   └── Security Features
└── Provider Implementations
    ├── NordVPN Provider
    ├── ExpressVPN Provider
    ├── Surfshark Provider
    ├── CyberGhost Provider
    ├── ProtonVPN Provider
    └── [Your Provider]
```

### **Provider Lifecycle**

1. **Registration**: Provider registered with factory
2. **Validation**: Security and interface compliance check
3. **Initialization**: Provider instance created
4. **Authentication**: User credentials validated
5. **Connection**: VPN connection established
6. **Monitoring**: Connection health tracked
7. **Disconnection**: Clean connection termination

## 🔌 Base Provider Interface

All VPN providers must implement the `BaseVPNProvider` abstract class.

### **Base Class Definition**

```python
# src/providers/base.py
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Tuple
import asyncio

class BaseVPNProvider(ABC):
    """Base class for all VPN providers."""
    
    def __init__(self, name: str):
        self.name = name
        self.connected = False
        self.current_server = None
        self.connection_start_time = None
        self.security_features = {}
    
    @abstractmethod
    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with the VPN provider."""
        pass
    
    @abstractmethod
    async def connect(self, server: str = None) -> bool:
        """Connect to the VPN service."""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """Disconnect from the VPN service."""
        pass
    
    @abstractmethod
    async def get_servers(self) -> List[Dict[str, Any]]:
        """Get list of available servers."""
        pass
    
    @abstractmethod
    async def get_connection_info(self) -> Dict[str, Any]:
        """Get current connection information."""
        pass
    
    @abstractmethod
    async def get_status(self) -> Dict[str, Any]:
        """Get current connection status."""
        pass
    
    # Optional methods for enhanced functionality
    async def get_server_recommendations(self, criteria: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Get recommended servers based on criteria."""
        return await self.get_servers()
    
    async def enable_kill_switch(self) -> bool:
        """Enable kill switch feature."""
        return False
    
    async def enable_dns_leak_protection(self) -> bool:
        """Enable DNS leak protection."""
        return False
    
    async def get_security_features(self) -> Dict[str, bool]:
        """Get available security features."""
        return self.security_features
```

## 🛠️ Implementation Guide

### **Step 1: Create Provider Class**

Create a new file `src/providers/yourprovider.py`:

```python
# src/providers/yourprovider.py
import asyncio
import json
import subprocess
from typing import Dict, List, Any, Optional

from .base import BaseVPNProvider
from ..security.input_sanitizer import InputSanitizer
from ..security.secure_command_executor import SecureCommandExecutor
from ..utils.logger import get_logger

class YourProviderVPN(BaseVPNProvider):
    """Your VPN Provider implementation."""
    
    def __init__(self):
        super().__init__("yourprovider")
        self.sanitizer = InputSanitizer()
        self.executor = SecureCommandExecutor()
        self.logger = get_logger(__name__)
        self.api_endpoint = "https://api.yourprovider.com"
        self.cli_command = "yourprovider-cli"
        
        # Define security features
        self.security_features = {
            'kill_switch': True,
            'dns_leak_protection': True,
            'auto_connect': True,
            'custom_dns': True,
            'split_tunneling': False,
            'malware_blocking': True
        }
    
    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with Your VPN Provider."""
        try:
            # Sanitize inputs
            clean_username = self.sanitizer.sanitize_username(username)
            clean_password = self.sanitizer.sanitize_password(password)
            
            # Execute authentication command securely
            result = self.executor.execute_command(
                [self.cli_command, 'login'],
                env_vars={
                    'YOURPROVIDER_USERNAME': clean_username,
                    'YOURPROVIDER_PASSWORD': clean_password
                }
            )
            
            if result.returncode == 0:
                self.logger.info("Authentication successful")
                return True
            else:
                self.logger.error(f"Authentication failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    async def connect(self, server: str = None) -> bool:
        """Connect to Your VPN Provider."""
        try:
            # Prepare command
            command = [self.cli_command, 'connect']
            
            if server:
                clean_server = self.sanitizer.sanitize_server_name(server)
                command.append(clean_server)
            
            # Execute connection command
            result = self.executor.execute_command(command)
            
            if result.returncode == 0:
                self.connected = True
                self.current_server = server
                self.connection_start_time = asyncio.get_event_loop().time()
                self.logger.info(f"Connected to {server or 'auto-selected server'}")
                return True
            else:
                self.logger.error(f"Connection failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Connection error: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from Your VPN Provider."""
        try:
            result = self.executor.execute_command([self.cli_command, 'disconnect'])
            
            if result.returncode == 0:
                self.connected = False
                self.current_server = None
                self.connection_start_time = None
                self.logger.info("Disconnected successfully")
                return True
            else:
                self.logger.error(f"Disconnection failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Disconnection error: {e}")
            return False
    
    async def get_servers(self) -> List[Dict[str, Any]]:
        """Get list of available servers."""
        try:
            result = self.executor.execute_command([self.cli_command, 'servers', '--json'])
            
            if result.returncode == 0:
                servers_data = json.loads(result.stdout)
                return self._parse_servers(servers_data)
            else:
                self.logger.error(f"Failed to get servers: {result.stderr}")
                return []
                
        except Exception as e:
            self.logger.error(f"Error getting servers: {e}")
            return []
    
    async def get_connection_info(self) -> Dict[str, Any]:
        """Get current connection information."""
        try:
            result = self.executor.execute_command([self.cli_command, 'status', '--json'])
            
            if result.returncode == 0:
                status_data = json.loads(result.stdout)
                return self._parse_connection_info(status_data)
            else:
                return {
                    'connected': False,
                    'server': None,
                    'ip_address': None,
                    'location': None
                }
                
        except Exception as e:
            self.logger.error(f"Error getting connection info: {e}")
            return {'connected': False}
    
    async def get_status(self) -> Dict[str, Any]:
        """Get current connection status."""
        connection_info = await self.get_connection_info()
        
        return {
            'provider': self.name,
            'connected': self.connected,
            'server': self.current_server,
            'connection_time': self.connection_start_time,
            **connection_info
        }
    
    # Provider-specific methods
    async def enable_kill_switch(self) -> bool:
        """Enable Your Provider's kill switch."""
        try:
            result = self.executor.execute_command([self.cli_command, 'set', 'killswitch', 'on'])
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Failed to enable kill switch: {e}")
            return False
    
    async def enable_dns_leak_protection(self) -> bool:
        """Enable DNS leak protection."""
        try:
            result = self.executor.execute_command([self.cli_command, 'set', 'dns', 'leak-protection', 'on'])
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Failed to enable DNS leak protection: {e}")
            return False
    
    async def enable_malware_blocking(self) -> bool:
        """Enable malware blocking feature."""
        try:
            result = self.executor.execute_command([self.cli_command, 'set', 'malware-blocking', 'on'])
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Failed to enable malware blocking: {e}")
            return False
    
    def _parse_servers(self, servers_data: List[Dict]) -> List[Dict[str, Any]]:
        """Parse server data from provider API."""
        parsed_servers = []
        
        for server in servers_data:
            parsed_servers.append({
                'name': server.get('hostname', ''),
                'country': server.get('country', ''),
                'city': server.get('city', ''),
                'load': server.get('load', 0),
                'distance': server.get('distance', 0),
                'features': server.get('features', []),
                'protocols': server.get('protocols', [])
            })
        
        return parsed_servers
    
    def _parse_connection_info(self, status_data: Dict) -> Dict[str, Any]:
        """Parse connection information from provider status."""
        return {
            'connected': status_data.get('connected', False),
            'server': status_data.get('server', {}).get('hostname'),
            'ip_address': status_data.get('ip_address'),
            'location': {
                'country': status_data.get('server', {}).get('country'),
                'city': status_data.get('server', {}).get('city'),
                'coordinates': {
                    'lat': status_data.get('server', {}).get('latitude'),
                    'lng': status_data.get('server', {}).get('longitude')
                }
            },
            'protocol': status_data.get('protocol'),
            'encryption': status_data.get('encryption')
        }
```

### **Step 2: Add Security Validation**

Ensure your provider follows security best practices:

```python
# src/providers/yourprovider.py (security additions)

class YourProviderVPN(BaseVPNProvider):
    def __init__(self):
        super().__init__("yourprovider")
        # ... existing initialization ...
        
        # Security configuration
        self.security_config = {
            'certificate_pinning': True,
            'tls_version': 'TLSv1.2',
            'verify_ssl': True,
            'timeout': 30
        }
    
    async def _validate_server_certificate(self, server: str) -> bool:
        """Validate server certificate for security."""
        try:
            # Implement certificate validation logic
            import ssl
            import socket
            
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((server, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=server) as ssock:
                    cert = ssock.getpeercert()
                    return cert is not None
        except Exception as e:
            self.logger.error(f"Certificate validation failed: {e}")
            return False
    
    async def _security_check(self) -> Dict[str, bool]:
        """Perform security checks before connection."""
        checks = {
            'input_validation': True,
            'certificate_valid': False,
            'kill_switch_ready': False,
            'dns_protection_ready': False
        }
        
        if self.current_server:
            checks['certificate_valid'] = await self._validate_server_certificate(self.current_server)
        
        # Add more security checks as needed
        return checks
```

### **Step 3: Provider Registration**

Register your provider with the factory:

```python
# src/providers/__init__.py
from .nordvpn import NordVPNProvider
from .expressvpn import ExpressVPNProvider
from .surfshark import SurfsharkProvider
from .cyberghost import CyberGhostProvider
from .protonvpn import ProtonVPNProvider
from .yourprovider import YourProviderVPN  # Add your provider

class VPNProviderFactory:
    """Factory for creating VPN provider instances."""
    
    _providers = {
        'nordvpn': NordVPNProvider,
        'expressvpn': ExpressVPNProvider,
        'surfshark': SurfsharkProvider,
        'cyberghost': CyberGhostProvider,
        'protonvpn': ProtonVPNProvider,
        'yourprovider': YourProviderVPN,  # Register your provider
    }
    
    @classmethod
    def create_provider(cls, provider_name: str) -> BaseVPNProvider:
        """Create a provider instance."""
        if provider_name not in cls._providers:
            raise ValueError(f"Unknown provider: {provider_name}")
        
        return cls._providers[provider_name]()
    
    @classmethod
    def get_available_providers(cls) -> List[str]:
        """Get list of available providers."""
        return list(cls._providers.keys())
```

## 🔒 Security Requirements

### **Mandatory Security Features**

1. **Input Sanitization**: All user inputs must be sanitized
2. **Secure Command Execution**: Use SecureCommandExecutor for all commands
3. **Credential Security**: Never store credentials in plain text
4. **Certificate Validation**: Validate SSL/TLS certificates
5. **Error Handling**: Secure error handling without information disclosure

### **Security Checklist**

```python
# Security validation for new providers
SECURITY_REQUIREMENTS = {
    'input_sanitization': True,
    'secure_command_execution': True,
    'credential_encryption': True,
    'certificate_validation': True,
    'error_handling': True,
    'logging_security': True,
    'timeout_handling': True,
    'privilege_management': True
}
```

### **Code Security Review**

Before integration, your provider must pass security review:

```python
# src/security/provider_validator.py
class ProviderSecurityValidator:
    """Validates provider security compliance."""
    
    @staticmethod
    def validate_provider(provider_class) -> Dict[str, bool]:
        """Validate provider security compliance."""
        results = {}
        
        # Check for required methods
        required_methods = [
            'authenticate', 'connect', 'disconnect',
            'get_servers', 'get_connection_info', 'get_status'
        ]
        
        for method in required_methods:
            results[f'has_{method}'] = hasattr(provider_class, method)
        
        # Check for security features
        instance = provider_class()
        results['uses_input_sanitizer'] = hasattr(instance, 'sanitizer')
        results['uses_secure_executor'] = hasattr(instance, 'executor')
        results['has_security_features'] = hasattr(instance, 'security_features')
        
        return results
```

## 🧪 Testing Integration

### **Unit Tests**

Create comprehensive tests for your provider:

```python
# tests/test_yourprovider.py
import pytest
import asyncio
from unittest.mock import Mock, patch

from src.providers.yourprovider import YourProviderVPN

class TestYourProviderVPN:
    """Test suite for Your Provider VPN."""
    
    @pytest.fixture
    def provider(self):
        """Create provider instance for testing."""
        return YourProviderVPN()
    
    @pytest.mark.asyncio
    async def test_authentication_success(self, provider):
        """Test successful authentication."""
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 0
            mock_exec.return_value.stderr = ""
            
            result = await provider.authenticate("test_user", "test_pass")
            assert result is True
    
    @pytest.mark.asyncio
    async def test_authentication_failure(self, provider):
        """Test failed authentication."""
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 1
            mock_exec.return_value.stderr = "Authentication failed"
            
            result = await provider.authenticate("bad_user", "bad_pass")
            assert result is False
    
    @pytest.mark.asyncio
    async def test_connection_success(self, provider):
        """Test successful connection."""
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 0
            
            result = await provider.connect("test-server.yourprovider.com")
            assert result is True
            assert provider.connected is True
            assert provider.current_server == "test-server.yourprovider.com"
    
    @pytest.mark.asyncio
    async def test_get_servers(self, provider):
        """Test getting server list."""
        mock_servers = [
            {"hostname": "us1.yourprovider.com", "country": "US", "city": "New York", "load": 15},
            {"hostname": "uk1.yourprovider.com", "country": "UK", "city": "London", "load": 25}
        ]
        
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 0
            mock_exec.return_value.stdout = json.dumps(mock_servers)
            
            servers = await provider.get_servers()
            assert len(servers) == 2
            assert servers[0]['name'] == "us1.yourprovider.com"
            assert servers[0]['country'] == "US"
    
    @pytest.mark.asyncio
    async def test_security_features(self, provider):
        """Test security features availability."""
        features = await provider.get_security_features()
        assert 'kill_switch' in features
        assert 'dns_leak_protection' in features
        assert features['kill_switch'] is True
```

### **Integration Tests**

```python
# tests/integration/test_provider_integration.py
import pytest
from src.core.vpn_manager import VPNManager
from src.providers.yourprovider import YourProviderVPN

class TestProviderIntegration:
    """Integration tests for provider with VPN Hub core."""
    
    @pytest.mark.asyncio
    async def test_provider_registration(self):
        """Test provider is properly registered."""
        vpn_manager = VPNManager()
        providers = vpn_manager.list_providers()
        assert 'yourprovider' in providers
    
    @pytest.mark.asyncio
    async def test_provider_creation(self):
        """Test provider can be created through factory."""
        vpn_manager = VPNManager()
        provider = vpn_manager.get_provider('yourprovider')
        assert isinstance(provider, YourProviderVPN)
    
    @pytest.mark.asyncio
    async def test_security_validation(self):
        """Test provider passes security validation."""
        from src.security.provider_validator import ProviderSecurityValidator
        
        validation_results = ProviderSecurityValidator.validate_provider(YourProviderVPN)
        assert all(validation_results.values()), f"Security validation failed: {validation_results}"
```

## 📋 Registration Process

### **Step 1: Provider Submission**

1. **Code Review**: Submit provider code for security review
2. **Testing**: Ensure all tests pass (unit + integration)
3. **Documentation**: Provide complete documentation
4. **Security Audit**: Pass security compliance check

### **Step 2: Quality Assurance**

```python
# Quality checks for provider integration
QUALITY_REQUIREMENTS = {
    'code_coverage': 90,  # Minimum test coverage
    'security_score': 100,  # Must pass all security checks
    'performance_benchmark': True,  # Meet performance standards
    'documentation_complete': True,  # Complete documentation
    'error_handling': True,  # Proper error handling
    'logging_standards': True,  # Follow logging standards
}
```

### **Step 3: Final Integration**

1. **Configuration**: Add provider to configuration files
2. **GUI Integration**: Add provider to GUI interface
3. **Documentation**: Update user documentation
4. **Release**: Include in next VPN Hub release

## 📖 Provider-Specific Examples

### **REST API Based Provider**

```python
import aiohttp
import json

class RestAPIProvider(BaseVPNProvider):
    """Example REST API based provider."""
    
    async def authenticate(self, username: str, password: str) -> bool:
        async with aiohttp.ClientSession() as session:
            auth_data = {
                'username': self.sanitizer.sanitize_username(username),
                'password': self.sanitizer.sanitize_password(password)
            }
            
            async with session.post(f"{self.api_endpoint}/auth", json=auth_data) as response:
                if response.status == 200:
                    auth_result = await response.json()
                    self.auth_token = auth_result.get('token')
                    return True
                return False
```

### **CLI Based Provider**

```python
class CLIProvider(BaseVPNProvider):
    """Example CLI based provider."""
    
    async def connect(self, server: str = None) -> bool:
        command = [self.cli_command, 'connect']
        if server:
            command.append(self.sanitizer.sanitize_server_name(server))
        
        result = self.executor.execute_command(command, timeout=30)
        return result.returncode == 0
```

## 📞 Support and Resources

### **Development Support**
- **Email**: provider-dev@vpnhub.local
- **Documentation**: Internal provider development guide
- **Code Review**: security-review@vpnhub.local

### **Testing Resources**
- **Test Environment**: Staging environment for provider testing
- **Security Scanner**: Automated security validation tools
- **Performance Testing**: Benchmarking and performance analysis

---

**Provider Integration Version:** 2.0  
**Last Updated:** November 1, 2025  
**For Support:** provider-integration@vpnhub.local