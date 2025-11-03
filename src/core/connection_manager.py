"""
VPN Connection Manager
Handles the orchestration of multiple VPN providers and manages connections
"""

import asyncio
import logging
from typing import Dict, List, Optional, Tuple, Callable
from datetime import datetime
import json
import time

try:
    from .vpn_interface import (
        VPNProviderInterface, ServerInfo, ConnectionInfo, 
        ConnectionStatus, ProtocolType
    )
    from ..providers import VPNProviderFactory
except ImportError:
    # Handle imports when running as standalone script
    import sys
    from pathlib import Path
    src_dir = Path(__file__).parent.parent
    sys.path.insert(0, str(src_dir))
    
    from core.vpn_interface import (
        VPNProviderInterface, ServerInfo, ConnectionInfo, 
        ConnectionStatus, ProtocolType
    )
    from providers import VPNProviderFactory

class VPNConnectionManager:
    """Manages connections across multiple VPN providers"""
    
    def __init__(self):
        self.providers: Dict[str, VPNProviderInterface] = {}
        self.active_provider: Optional[VPNProviderInterface] = None
        self.connection_history: List[Dict] = []
        self.auto_reconnect = True
        self.preferred_protocol = ProtocolType.OPENVPN
        self.kill_switch_enabled = True
        self.dns_protection_enabled = True
        self.connection_callbacks: List[Callable] = []
        
        # Setup logging
        logging.basicConfig(
            filename='logs/vpn_manager.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def add_provider(self, name: str, config: Dict) -> bool:
        """Add a VPN provider to the manager"""
        try:
            provider = VPNProviderFactory.create_provider(name, config)
            if provider:
                self.providers[name] = provider
                self.logger.info(f"Added VPN provider: {name}")
                return True
            else:
                self.logger.error(f"Failed to create provider: {name}")
                return False
        except Exception as e:
            self.logger.error(f"Error adding provider {name}: {e}")
            return False
    
    def remove_provider(self, name: str) -> bool:
        """Remove a VPN provider from the manager"""
        try:
            if name in self.providers:
                # Disconnect if this is the active provider
                if self.active_provider and self.active_provider.name == name:
                    asyncio.create_task(self.disconnect())
                
                del self.providers[name]
                self.logger.info(f"Removed VPN provider: {name}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Error removing provider {name}: {e}")
            return False
    
    async def authenticate_provider(self, name: str, username: str, password: str) -> bool:
        """Authenticate with a specific VPN provider"""
        try:
            if name not in self.providers:
                self.logger.error(f"Provider {name} not found")
                return False
            
            provider = self.providers[name]
            success = await provider.authenticate(username, password)
            
            if success:
                self.logger.info(f"Successfully authenticated with {name}")
            else:
                self.logger.error(f"Authentication failed for {name}")
            
            return success
        except Exception as e:
            self.logger.error(f"Error authenticating with {name}: {e}")
            return False
    
    async def get_all_servers(self, country: str = None) -> Dict[str, List[ServerInfo]]:
        """Get servers from all authenticated providers"""
        all_servers = {}
        
        for name, provider in self.providers.items():
            if provider.is_authenticated:
                try:
                    # Special handling for ExpressVPN subscription verification
                    if name.lower() == 'expressvpn' and hasattr(provider, 'check_subscription_status'):
                        # Check subscription before loading servers
                        subscription_active = await provider.check_subscription_status()
                        if not subscription_active:
                            print(f"⚠️  ExpressVPN: Consider activating subscription for full access")
                    
                    servers = await provider.get_servers(country)
                    all_servers[name] = servers
                    self.logger.info(f"Retrieved {len(servers)} servers from {name}")
                except Exception as e:
                    self.logger.error(f"Error getting servers from {name}: {e}")
                    all_servers[name] = []
        
        return all_servers
    
    async def connect_to_provider(self, provider_name: str, server: ServerInfo, 
                                protocol: ProtocolType = None) -> bool:
        """Connect to a specific provider and server"""
        try:
            if provider_name not in self.providers:
                self.logger.error(f"Provider {provider_name} not found")
                return False
            
            provider = self.providers[provider_name]
            
            if not provider.is_authenticated:
                self.logger.error(f"Provider {provider_name} not authenticated")
                return False
            
            # Disconnect from current provider if connected
            if self.active_provider:
                await self.disconnect()
            
            # Connect to new provider
            protocol = protocol or self.preferred_protocol
            success = await provider.connect(server, protocol)
            
            if success:
                self.active_provider = provider
                self.logger.info(f"Connected to {provider_name} - {server.name}")
                
                # Record connection in history
                self._record_connection(provider_name, server, protocol)
                
                # Notify callbacks
                await self._notify_connection_callbacks("connected", provider_name, server)
                
                return True
            else:
                self.logger.error(f"Failed to connect to {provider_name} - {server.name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error connecting to {provider_name}: {e}")
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from current VPN provider"""
        try:
            if not self.active_provider:
                self.logger.info("No active connection to disconnect")
                return True
            
            provider_name = self.active_provider.name
            success = await self.active_provider.disconnect()
            
            if success:
                self.logger.info(f"Disconnected from {provider_name}")
                await self._notify_connection_callbacks("disconnected", provider_name, None)
                self.active_provider = None
                return True
            else:
                self.logger.error(f"Failed to disconnect from {provider_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error disconnecting: {e}")
            return False
    
    async def get_connection_status(self) -> Optional[ConnectionInfo]:
        """Get current connection status"""
        try:
            if self.active_provider:
                return await self.active_provider.get_connection_status()
            return None
        except Exception as e:
            self.logger.error(f"Error getting connection status: {e}")
            return None
    
    async def get_public_ip(self) -> Optional[str]:
        """Get current public IP address"""
        try:
            if self.active_provider:
                return await self.active_provider.get_public_ip()
            return None
        except Exception as e:
            self.logger.error(f"Error getting public IP: {e}")
            return None
    
    async def test_all_connections(self) -> Dict[str, Tuple[bool, float]]:
        """Test connection speed for all authenticated providers"""
        results = {}
        
        for name, provider in self.providers.items():
            if provider.is_authenticated:
                try:
                    success, latency = await provider.test_connection()
                    results[name] = (success, latency)
                    self.logger.info(f"Connection test for {name}: {success}, {latency}ms")
                except Exception as e:
                    self.logger.error(f"Error testing connection for {name}: {e}")
                    results[name] = (False, 0)
        
        return results
    
    async def auto_connect_best_server(self, country: str = None) -> bool:
        """Automatically connect to the best available server"""
        try:
            # Get all servers
            all_servers = await self.get_all_servers(country)
            
            if not all_servers:
                self.logger.error("No servers available for auto-connect")
                return False
            
            best_provider = None
            best_server = None
            best_score = 0
            
            # Find best server based on load and features
            for provider_name, servers in all_servers.items():
                if not servers:
                    continue
                
                for server in servers:
                    # Calculate score based on load (lower is better) and features
                    score = 100 - server.load
                    if "High Speed" in (server.features or []):
                        score += 20
                    if "P2P" in (server.features or []):
                        score += 10
                    
                    if score > best_score:
                        best_score = score
                        best_provider = provider_name
                        best_server = server
            
            if best_provider and best_server:
                return await self.connect_to_provider(best_provider, best_server)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error in auto-connect: {e}")
            return False
    
    def add_connection_callback(self, callback: Callable):
        """Add a callback function for connection events"""
        self.connection_callbacks.append(callback)
    
    def remove_connection_callback(self, callback: Callable):
        """Remove a connection callback"""
        if callback in self.connection_callbacks:
            self.connection_callbacks.remove(callback)
    
    def get_connection_history(self) -> List[Dict]:
        """Get connection history"""
        return self.connection_history.copy()
    
    def get_provider_stats(self) -> Dict[str, Dict]:
        """Get statistics for each provider"""
        stats = {}
        
        for name, provider in self.providers.items():
            stats[name] = {
                "name": provider.name,
                "authenticated": provider.is_authenticated,
                "supported_protocols": [p.value for p in asyncio.run(provider.get_supported_protocols())],
                "last_connected": self._get_last_connection_time(name)
            }
        
        return stats
    
    def _record_connection(self, provider_name: str, server: ServerInfo, protocol: ProtocolType):
        """Record a connection in history"""
        connection_record = {
            "timestamp": datetime.now().isoformat(),
            "provider": provider_name,
            "server": {
                "name": server.name,
                "country": server.country,
                "city": server.city,
                "ip": server.ip_address
            },
            "protocol": protocol.value if protocol else None
        }
        
        self.connection_history.append(connection_record)
        
        # Keep only last 100 connections
        if len(self.connection_history) > 100:
            self.connection_history = self.connection_history[-100:]
    
    async def _notify_connection_callbacks(self, event: str, provider: str, server: Optional[ServerInfo]):
        """Notify all registered callbacks about connection events"""
        for callback in self.connection_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event, provider, server)
                else:
                    callback(event, provider, server)
            except Exception as e:
                self.logger.error(f"Error in connection callback: {e}")
    
    def _get_last_connection_time(self, provider_name: str) -> Optional[str]:
        """Get the last connection time for a provider"""
        for record in reversed(self.connection_history):
            if record["provider"] == provider_name:
                return record["timestamp"]
        return None
    
    async def emergency_disconnect(self) -> bool:
        """Emergency disconnect with kill switch activation"""
        try:
            if self.kill_switch_enabled:
                # Implement kill switch logic here
                self.logger.warning("Kill switch activated - blocking internet")
                # This would typically involve firewall rules or route manipulation
            
            return await self.disconnect()
            
        except Exception as e:
            self.logger.error(f"Error in emergency disconnect: {e}")
            return False
