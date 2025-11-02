"""
NordVPN Provider Implementation - SECURITY HARDENED
Handles connections and management for NordVPN services with secure command execution
"""

import asyncio
import json
import aiohttp
from typing import List, Dict, Optional, Tuple
try:
    from ..core.vpn_interface import VPNProviderInterface, ServerInfo, ConnectionInfo, ConnectionStatus, ProtocolType
    from ..security.secure_command_executor import SecureCommandExecutor
    from ..security.input_sanitizer import InputSanitizer, SecurityException
except ImportError:
    # Handle imports when running as standalone script
    import sys
    from pathlib import Path
    src_dir = Path(__file__).parent.parent
    sys.path.insert(0, str(src_dir))
    
    from core.vpn_interface import VPNProviderInterface, ServerInfo, ConnectionInfo, ConnectionStatus, ProtocolType
    from security.secure_command_executor import SecureCommandExecutor
    from security.input_sanitizer import InputSanitizer, SecurityException

class NordVPNProvider(VPNProviderInterface):
    """NordVPN provider implementation with enhanced security"""
    
    def __init__(self, config: Dict):
        super().__init__("NordVPN", config)
        self.api_base = "https://api.nordvpn.com"
        self.session = None
        self.secure_executor = SecureCommandExecutor()
        
    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with NordVPN using secure command execution"""
        try:
            # Use secure authentication through SecureCommandExecutor
            success, message = await self.secure_executor.execute_vpn_auth(
                'nordvpn', username, password
            )
            
            if success:
                self.is_authenticated = True
                return True
            else:
                # Log sanitized error (no credentials exposed)
                user_hash = InputSanitizer.hash_sensitive_data(username)
                print(f"NordVPN authentication failed for user {user_hash}")
                return False
                
        except SecurityException as e:
            print(f"NordVPN authentication security error: {e}")
            return False
        except Exception as e:
            print(f"NordVPN authentication error: {e}")
            return False
    
    async def get_servers(self, country: str = None) -> List[ServerInfo]:
        """Get list of available NordVPN servers"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.api_base}/v1/servers"
                params = {}
                if country:
                    params['filters[country_id]'] = country
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        servers = []
                        
                        for server_data in data:
                            server = ServerInfo(
                                id=str(server_data['id']),
                                name=server_data['name'],
                                country=server_data['locations'][0]['country']['name'],
                                city=server_data['locations'][0]['country']['city']['name'],
                                ip_address=server_data['station'],
                                load=server_data['load'],
                                protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2],
                                features=server_data.get('features', [])
                            )
                            servers.append(server)
                        
                        return servers
                    else:
                        print(f"Failed to get NordVPN servers: {response.status}")
                        return []
        except Exception as e:
            print(f"Error getting NordVPN servers: {e}")
            return []
    
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to NordVPN server using secure execution"""
        try:
            # Sanitize server name
            server_name = InputSanitizer.sanitize_server_name(server.name)
            
            # Map protocol type to NordVPN protocol string
            protocol_str = None
            if protocol == ProtocolType.OPENVPN:
                protocol_str = "openvpn"
            elif protocol == ProtocolType.IKEV2:
                protocol_str = "ikev2"
            
            # Use secure command execution
            success, message = await self.secure_executor.execute_vpn_connect(
                'nordvpn', server_name, protocol_str
            )
            
            if success:
                self.connection_info.status = ConnectionStatus.CONNECTED
                self.connection_info.server = server
                self.connection_info.protocol = protocol
                return True
            else:
                print(f"NordVPN connection failed: {message}")
                self.connection_info.status = ConnectionStatus.ERROR
                return False
                
        except SecurityException as e:
            print(f"NordVPN connection security error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return False
        except Exception as e:
            print(f"NordVPN connection error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from NordVPN using secure execution"""
        try:
            # Use secure command execution
            success, message = await self.secure_executor.execute_vpn_disconnect('nordvpn')
            
            if success:
                self.connection_info.status = ConnectionStatus.DISCONNECTED
                self.connection_info.server = None
                return True
            else:
                print(f"NordVPN disconnect failed: {message}")
                return False
                
        except SecurityException as e:
            print(f"NordVPN disconnect security error: {e}")
            return False
        except Exception as e:
            print(f"NordVPN disconnect error: {e}")
            return False
    
    async def get_connection_status(self) -> ConnectionInfo:
        """Get current NordVPN connection status using secure execution"""
        try:
            # Use secure command execution
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(['nordvpn', 'status'])
            
            if return_code == 0:
                output = stdout
                if "Connected" in output:
                    self.connection_info.status = ConnectionStatus.CONNECTED
                    # Parse additional info from status output
                    lines = output.split('\n')
                    for line in lines:
                        if "Current server:" in line:
                            server_name = line.split(': ')[1]
                        elif "Current IP:" in line:
                            self.connection_info.public_ip = line.split(': ')[1]
                else:
                    self.connection_info.status = ConnectionStatus.DISCONNECTED
            else:
                self.connection_info.status = ConnectionStatus.ERROR
            
            return self.connection_info
            
        except SecurityException as e:
            print(f"NordVPN status security error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return self.connection_info
        except Exception as e:
            print(f"Error getting NordVPN status: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return self.connection_info
    
    async def get_public_ip(self) -> str:
        """Get current public IP address"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("https://api.ipify.org?format=json") as response:
                    if response.status == 200:
                        data = await response.json()
                        return data['ip']
            return None
        except Exception as e:
            print(f"Error getting public IP: {e}")
            return None
    
    async def test_connection(self) -> Tuple[bool, float]:
        """Test NordVPN connection speed"""
        try:
            import time
            start_time = time.time()
            
            async with aiohttp.ClientSession() as session:
                async with session.get("https://www.google.com", timeout=10) as response:
                    if response.status == 200:
                        end_time = time.time()
                        latency = (end_time - start_time) * 1000  # Convert to milliseconds
                        return True, latency
            return False, 0
        except Exception as e:
            print(f"Connection test failed: {e}")
            return False, 0
    
    async def get_supported_protocols(self) -> List[ProtocolType]:
        """Get supported protocols for NordVPN"""
        return [ProtocolType.OPENVPN, ProtocolType.IKEV2]