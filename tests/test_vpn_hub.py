"""
Unit tests for VPN Hub components
Run with: python -m pytest tests/ or python test_vpn_hub.py
"""

import pytest
import asyncio
import os
import tempfile
import shutil
from unittest.mock import Mock, patch, AsyncMock

# Import the modules to test
import sys
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_dir))

try:
    from core.vpn_interface import VPNProviderInterface, ServerInfo, ConnectionStatus, ProtocolType
    from core.connection_manager import VPNConnectionManager
    from core.config_manager import ConfigurationManager
    from security.security_manager import SecurityManager
    from providers.nordvpn import NordVPNProvider
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running this from the tests directory")
    sys.exit(1)

class TestVPNInterface:
    """Test the VPN interface and base classes"""
    
    def test_server_info_creation(self):
        """Test ServerInfo dataclass creation"""
        server = ServerInfo(
            id="test-server-1",
            name="Test Server",
            country="United States",
            city="New York",
            ip_address="192.168.1.1",
            load=25.5,
            protocols=[ProtocolType.OPENVPN, ProtocolType.WIREGUARD]
        )
        
        assert server.id == "test-server-1"
        assert server.name == "Test Server"
        assert server.country == "United States"
        assert server.load == 25.5
        assert ProtocolType.OPENVPN in server.protocols
    
    def test_connection_status_enum(self):
        """Test ConnectionStatus enum values"""
        assert ConnectionStatus.DISCONNECTED.value == "disconnected"
        assert ConnectionStatus.CONNECTED.value == "connected"
        assert ConnectionStatus.CONNECTING.value == "connecting"
        assert ConnectionStatus.ERROR.value == "error"
    
    def test_protocol_type_enum(self):
        """Test ProtocolType enum values"""
        assert ProtocolType.OPENVPN.value == "openvpn"
        assert ProtocolType.WIREGUARD.value == "wireguard"
        assert ProtocolType.IKEV2.value == "ikev2"

class TestConnectionManager:
    """Test the VPN connection manager"""
    
    @pytest.fixture
    def manager(self):
        """Create a connection manager for testing"""
        return VPNConnectionManager()
    
    def test_manager_initialization(self, manager):
        """Test manager initializes correctly"""
        assert manager.providers == {}
        assert manager.active_provider is None
        assert manager.connection_history == []
        assert manager.kill_switch_enabled is True
    
    def test_add_provider(self, manager):
        """Test adding a VPN provider"""
        config = {"api_key": "test_key"}
        success = manager.add_provider("nordvpn", config)
        
        assert success is True
        assert "nordvpn" in manager.providers
        assert manager.providers["nordvpn"].name == "NordVPN"
    
    def test_remove_provider(self, manager):
        """Test removing a VPN provider"""
        # First add a provider
        config = {"api_key": "test_key"}
        manager.add_provider("nordvpn", config)
        
        # Then remove it
        success = manager.remove_provider("nordvpn")
        assert success is True
        assert "nordvpn" not in manager.providers
    
    @pytest.mark.asyncio
    async def test_authenticate_provider(self, manager):
        """Test provider authentication"""
        config = {"api_key": "test_key"}
        manager.add_provider("nordvpn", config)
        
        # Mock the authentication method
        with patch.object(manager.providers["nordvpn"], 'authenticate', return_value=True):
            success = await manager.authenticate_provider("nordvpn", "test_user", "test_pass")
            assert success is True

class TestConfigurationManager:
    """Test the configuration manager"""
    
    @pytest.fixture
    def temp_config_dir(self):
        """Create a temporary directory for testing"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def config_manager(self, temp_config_dir):
        """Create a configuration manager with temp directory"""
        return ConfigurationManager(config_dir=temp_config_dir)
    
    def test_config_manager_initialization(self, config_manager):
        """Test configuration manager initializes correctly"""
        assert config_manager.config is not None
        assert config_manager.settings is not None
        assert config_manager.providers is not None
    
    def test_add_provider_config(self, config_manager):
        """Test adding provider configuration"""
        provider_config = {
            "name": "NordVPN",
            "username": "test_user",
            "password": "test_pass",
            "enabled": True
        }
        
        success = config_manager.add_provider("nordvpn", provider_config)
        assert success is True
        
        retrieved = config_manager.get_provider("nordvpn")
        assert retrieved is not None
        assert retrieved["name"] == "NordVPN"
        assert retrieved["username"] == "test_user"
    
    def test_update_setting(self, config_manager):
        """Test updating application settings"""
        success = config_manager.update_setting("security", "kill_switch_enabled", False)
        assert success is True
        
        value = config_manager.get_setting("security", "kill_switch_enabled")
        assert value is False
    
    def test_export_import_config(self, config_manager, temp_config_dir):
        """Test configuration export and import"""
        # Add some test data
        config_manager.add_provider("nordvpn", {
            "name": "NordVPN",
            "username": "test_user",
            "password": "test_pass"
        })
        
        # Export configuration
        export_path = os.path.join(temp_config_dir, "export.json")
        success = config_manager.export_config(export_path, include_credentials=False)
        assert success is True
        assert os.path.exists(export_path)
        
        # Import configuration to a new manager
        new_manager = ConfigurationManager(config_dir=temp_config_dir + "_new")
        success = new_manager.import_config(export_path)
        assert success is True

class TestSecurityManager:
    """Test the security manager"""
    
    @pytest.fixture
    def security_manager(self):
        """Create a security manager for testing"""
        return SecurityManager()
    
    def test_security_manager_initialization(self, security_manager):
        """Test security manager initializes correctly"""
        assert security_manager.kill_switch_enabled is True
        assert security_manager.dns_protection_enabled is True
        assert security_manager.is_kill_switch_active is False
    
    @pytest.mark.asyncio
    async def test_check_for_leaks(self, security_manager):
        """Test leak detection functionality"""
        # Mock the leak detection methods
        with patch.object(security_manager, '_check_ip_leak', return_value=False), \
             patch.object(security_manager, '_check_dns_leak', return_value=False), \
             patch.object(security_manager, '_check_ipv6_leak', return_value=False):
            
            leak_results = await security_manager.check_for_leaks()
            
            assert leak_results["ip_leak"] is False
            assert leak_results["dns_leak"] is False
            assert leak_results["ipv6_leak"] is False
            assert leak_results["webrtc_leak"] is False

class TestNordVPNProvider:
    """Test the NordVPN provider implementation"""
    
    @pytest.fixture
    def nordvpn_provider(self):
        """Create a NordVPN provider for testing"""
        config = {"api_key": "test_key"}
        return NordVPNProvider(config)
    
    def test_provider_initialization(self, nordvpn_provider):
        """Test NordVPN provider initializes correctly"""
        assert nordvpn_provider.name == "NordVPN"
        assert nordvpn_provider.is_authenticated is False
        assert nordvpn_provider.api_base == "https://api.nordvpn.com"
    
    @pytest.mark.asyncio
    async def test_get_supported_protocols(self, nordvpn_provider):
        """Test getting supported protocols"""
        protocols = await nordvpn_provider.get_supported_protocols()
        
        assert ProtocolType.OPENVPN in protocols
        assert ProtocolType.IKEV2 in protocols

class TestIntegration:
    """Integration tests for the complete system"""
    
    @pytest.fixture
    def temp_config_dir(self):
        """Create a temporary directory for testing"""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.mark.asyncio
    async def test_full_workflow(self, temp_config_dir):
        """Test a complete workflow from configuration to connection"""
        # Initialize components
        config_manager = ConfigurationManager(config_dir=temp_config_dir)
        connection_manager = VPNConnectionManager()
        security_manager = SecurityManager()
        
        # Add provider configuration
        provider_config = {
            "name": "NordVPN",
            "username": "test_user",
            "password": "test_pass",
            "enabled": True
        }
        
        config_success = config_manager.add_provider("nordvpn", provider_config)
        assert config_success is True
        
        # Add provider to connection manager
        manager_success = connection_manager.add_provider("nordvpn", {})
        assert manager_success is True
        
        # Test security features
        leak_results = await security_manager.check_for_leaks()
        assert isinstance(leak_results, dict)
        assert "ip_leak" in leak_results

# Test fixtures and utilities

@pytest.fixture
def mock_server():
    """Create a mock server for testing"""
    return ServerInfo(
        id="test-server",
        name="Test Server",
        country="Test Country",
        city="Test City",
        ip_address="192.168.1.1",
        load=0,
        protocols=[ProtocolType.OPENVPN]
    )

@pytest.fixture
def mock_vpn_provider():
    """Create a mock VPN provider for testing"""
    provider = Mock(spec=VPNProviderInterface)
    provider.name = "MockVPN"
    provider.is_authenticated = True
    provider.authenticate = AsyncMock(return_value=True)
    provider.get_servers = AsyncMock(return_value=[])
    provider.connect = AsyncMock(return_value=True)
    provider.disconnect = AsyncMock(return_value=True)
    provider.get_connection_status = AsyncMock()
    provider.get_public_ip = AsyncMock(return_value="1.2.3.4")
    provider.test_connection = AsyncMock(return_value=(True, 50.0))
    provider.get_supported_protocols = AsyncMock(return_value=[ProtocolType.OPENVPN])
    
    return provider

# Performance tests

class TestPerformance:
    """Performance tests for critical components"""
    
    @pytest.mark.asyncio
    async def test_connection_manager_performance(self):
        """Test connection manager performance with multiple providers"""
        import time
        
        manager = VPNConnectionManager()
        
        # Add multiple providers
        start_time = time.time()
        for i in range(10):
            manager.add_provider(f"provider_{i}", {})
        
        end_time = time.time()
        
        # Should be able to add 10 providers in less than 1 second
        assert (end_time - start_time) < 1.0
    
    def test_config_manager_performance(self):
        """Test configuration manager performance with large datasets"""
        import time
        
        with tempfile.TemporaryDirectory() as temp_dir:
            config_manager = ConfigurationManager(config_dir=temp_dir)
            
            # Add many providers
            start_time = time.time()
            for i in range(100):
                config_manager.add_provider(f"provider_{i}", {
                    "name": f"Provider {i}",
                    "username": f"user_{i}",
                    "password": f"pass_{i}"
                })
            
            end_time = time.time()
            
            # Should be able to add 100 providers in less than 5 seconds
            assert (end_time - start_time) < 5.0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])