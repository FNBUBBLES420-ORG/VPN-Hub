"""
Surfshark VPN Provider Implementation - SECURITY HARDENED
Handles connections and management for Surfshark VPN services with secure command execution
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

class SurfsharkProvider(VPNProviderInterface):
    """Surfshark VPN provider implementation with enhanced security"""
    
    def __init__(self, config: Dict):
        super().__init__("Surfshark", config)
        self.api_base = "https://api.surfshark.com"
        self.secure_executor = SecureCommandExecutor()
        
    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with Surfshark VPN using secure command execution"""
        try:
            # Use secure authentication through SecureCommandExecutor
            success, message = await self.secure_executor.execute_vpn_auth(
                'surfshark-vpn', username, password
            )
            
            if success:
                self.is_authenticated = True
                return True
            else:
                # Log sanitized error (no credentials exposed)
                user_hash = InputSanitizer.hash_sensitive_data(username)
                print(f"Surfshark authentication failed for user {user_hash}")
                return False
                
        except SecurityException as e:
            print(f"Surfshark authentication security error: {e}")
            return False
        except Exception as e:
            print(f"Surfshark authentication error: {e}")
            return False
    
    async def get_servers(self, country: str = None) -> List[ServerInfo]:
        """Get list of available Surfshark servers"""
        try:
            # Get server list from Surfshark CLI
            process = await asyncio.create_subprocess_exec(
                "surfshark-vpn", "server", "list",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            servers = []
            if process.returncode == 0:
                output = stdout.decode()
                lines = output.split('\n')
                
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('Country') and not line.startswith('---'):
                        parts = line.split()
                        if len(parts) >= 2:
                            country_name = parts[0]
                            server_count = parts[1] if len(parts) > 1 else "1"
                            
                            # Create server entries for each country
                            server = ServerInfo(
                                id=country_name.lower().replace(' ', '_'),
                                name=f"{country_name} Server",
                                country=country_name,
                                city=country_name,  # Surfshark typically shows country level
                                ip_address="",  # Not exposed by CLI
                                load=0,  # Not available in CLI
                                protocols=[ProtocolType.OPENVPN, ProtocolType.WIREGUARD, ProtocolType.IKEV2],
                                features=["MultiHop", "No Logs", "P2P"]
                            )
                            
                            if not country or country.lower() in country_name.lower():
                                servers.append(server)
                
                return servers
            else:
                print(f"Failed to get Surfshark servers: {stderr.decode()}")
                return []
        except Exception as e:
            print(f"Error getting Surfshark servers: {e}")
            return []
    
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to Surfshark server"""
        try:
            cmd = ["surfshark-vpn", "connect"]
            
            # Add server location
            if server.country:
                cmd.extend(["-l", server.country])
            
            # Add protocol if specified
            if protocol == ProtocolType.WIREGUARD:
                cmd.extend(["-p", "wireguard"])
            elif protocol == ProtocolType.OPENVPN:
                cmd.extend(["-p", "openvpn"])
            elif protocol == ProtocolType.IKEV2:
                cmd.extend(["-p", "ikev2"])
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if "Connected" in stdout.decode() or process.returncode == 0:
                self.connection_info.status = ConnectionStatus.CONNECTED
                self.connection_info.server = server
                self.connection_info.protocol = protocol or ProtocolType.OPENVPN
                return True
            else:
                print(f"Surfshark connection failed: {stderr.decode()}")
                self.connection_info.status = ConnectionStatus.ERROR
                return False
        except Exception as e:
            print(f"Surfshark connection error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from Surfshark"""
        try:
            process = await asyncio.create_subprocess_exec(
                "surfshark-vpn", "disconnect",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if "Disconnected" in stdout.decode() or process.returncode == 0:
                self.connection_info.status = ConnectionStatus.DISCONNECTED
                self.connection_info.server = None
                return True
            else:
                print(f"Surfshark disconnect failed: {stderr.decode()}")
                return False
        except Exception as e:
            print(f"Surfshark disconnect error: {e}")
            return False
    
    async def get_connection_status(self) -> ConnectionInfo:
        """Get current Surfshark connection status"""
        try:
            process = await asyncio.create_subprocess_exec(
                "surfshark-vpn", "status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                if "Connected" in output:
                    self.connection_info.status = ConnectionStatus.CONNECTED
                    # Parse connection details
                    lines = output.split('\n')
                    for line in lines:
                        if "Server:" in line:
                            server_info = line.split("Server: ")[1] if "Server: " in line else ""
                        elif "IP:" in line:
                            self.connection_info.public_ip = line.split("IP: ")[1] if "IP: " in line else ""
                elif "Disconnected" in output or "Not connected" in output:
                    self.connection_info.status = ConnectionStatus.DISCONNECTED
            
            return self.connection_info
        except Exception as e:
            print(f"Error getting Surfshark status: {e}")
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
        """Test Surfshark connection speed"""
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
        """Get supported protocols for Surfshark"""
        return [ProtocolType.OPENVPN, ProtocolType.WIREGUARD, ProtocolType.IKEV2]