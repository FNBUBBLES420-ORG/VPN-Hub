"""
ExpressVPN Provider Implementation - SECURITY HARDENED
Handles connections and management for ExpressVPN services with secure command execution
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

class ExpressVPNProvider(VPNProviderInterface):
    """ExpressVPN provider implementation with enhanced security"""
    
    def __init__(self, config: Dict):
        super().__init__("ExpressVPN", config)
        self.api_base = "https://www.expressvpn.com/api"
        self.secure_executor = SecureCommandExecutor()
        
    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with ExpressVPN using secure command execution"""
        try:
            # Use secure authentication through SecureCommandExecutor
            success, message = await self.secure_executor.execute_vpn_auth(
                'expressvpn', username, password
            )
            
            if success:
                self.is_authenticated = True
                return True
            else:
                # Log sanitized error (no credentials exposed)
                user_hash = InputSanitizer.hash_sensitive_data(username)
                print(f"ExpressVPN authentication failed for user {user_hash}")
                return False
                
        except SecurityException as e:
            print(f"ExpressVPN authentication security error: {e}")
            return False
        except Exception as e:
            print(f"ExpressVPN authentication error: {e}")
            return False
    
    async def get_servers(self, country: str = None) -> List[ServerInfo]:
        """Get list of available ExpressVPN servers using secure execution"""
        try:
            # Use secure command execution
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(['expressvpn', 'list'])
            
            if return_code == 0:
                output = stdout
                servers = []
                lines = output.split('\n')
                
                for line in lines:
                    if line.strip() and not line.startswith('ALIAS'):
                        parts = line.split()
                        if len(parts) >= 2:
                            alias = parts[0]
                            location = ' '.join(parts[1:])
                            
                            # Parse location to extract country and city
                            if '-' in location:
                                country_city = location.split('-')
                                country = country_city[0].strip()
                                city = country_city[1].strip() if len(country_city) > 1 else country
                            else:
                                country = location.strip()
                                city = location.strip()
                            
                            if not country or (country and country.lower() == country.lower()):
                                server = ServerInfo(
                                    id=alias,
                                    name=alias,
                                    country=country,
                                    city=city,
                                    ip_address="",  # ExpressVPN doesn't expose IPs
                                    load=0,  # Not available
                                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.L2TP],
                                    features=["High Speed", "Netflix"]
                                )
                                servers.append(server)
                
                return servers
            else:
                print(f"Failed to get ExpressVPN servers: {stderr}")
                return []
        except SecurityException as e:
            print(f"ExpressVPN server list security error: {e}")
            return []
        except Exception as e:
            print(f"Error getting ExpressVPN servers: {e}")
            return []
    
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to ExpressVPN server using secure execution"""
        try:
            # Sanitize server ID
            server_id = InputSanitizer.sanitize_server_name(server.id)
            
            # Use secure command execution
            success, message = await self.secure_executor.execute_vpn_connect(
                'expressvpn', server_id
            )
            
            if success:
                self.connection_info.status = ConnectionStatus.CONNECTED
                self.connection_info.server = server
                self.connection_info.protocol = protocol or ProtocolType.OPENVPN
                return True
            else:
                print(f"ExpressVPN connection failed: {message}")
                self.connection_info.status = ConnectionStatus.ERROR
                return False
                
        except SecurityException as e:
            print(f"ExpressVPN connection security error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return False
        except Exception as e:
            print(f"ExpressVPN connection error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from ExpressVPN using secure execution"""
        try:
            # Use secure command execution
            success, message = await self.secure_executor.execute_vpn_disconnect('expressvpn')
            
            if success:
                self.connection_info.status = ConnectionStatus.DISCONNECTED
                self.connection_info.server = None
                return True
            else:
                print(f"ExpressVPN disconnect failed: {message}")
                return False
                
        except SecurityException as e:
            print(f"ExpressVPN disconnect security error: {e}")
            return False
        except Exception as e:
            print(f"ExpressVPN disconnect error: {e}")
            return False
    
    async def get_connection_status(self) -> ConnectionInfo:
        """Get current ExpressVPN connection status"""
        try:
            process = await asyncio.create_subprocess_exec(
                "expressvpn", "status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                if "Connected to" in output:
                    self.connection_info.status = ConnectionStatus.CONNECTED
                    # Parse server info from status
                    lines = output.split('\n')
                    for line in lines:
                        if "Connected to" in line:
                            server_name = line.split("Connected to ")[1]
                            break
                elif "Not connected" in output:
                    self.connection_info.status = ConnectionStatus.DISCONNECTED
            
            return self.connection_info
        except Exception as e:
            print(f"Error getting ExpressVPN status: {e}")
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
        """Test ExpressVPN connection speed"""
        try:
            import time
            start_time = time.time()
            
            async with aiohttp.ClientSession() as session:
                async with session.get("https://www.google.com", timeout=10) as response:
                    if response.status == 200:
                        end_time = time.time()
                        latency = (end_time - start_time) * 1000
                        return True, latency
            return False, 0
        except Exception as e:
            print(f"Connection test failed: {e}")
            return False, 0
    
    async def get_supported_protocols(self) -> List[ProtocolType]:
        """Get supported protocols for ExpressVPN"""
        return [ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.L2TP]