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
            # ExpressVPN uses GUI authentication - launch the application
            success, message = await self.secure_executor.execute_vpn_auth(
                'expressvpn', username, password
            )
            
            if success:
                self.is_authenticated = True
                print(f"ExpressVPN: {message}")
                return True
            else:
                # Log sanitized error (no credentials exposed)
                user_hash = InputSanitizer.hash_sensitive_data(username)
                print(f"ExpressVPN authentication info for user {user_hash}: {message}")
                return False
                
        except SecurityException as e:
            print(f"ExpressVPN authentication security error: {e}")
            return False
        except Exception as e:
            print(f"ExpressVPN authentication error: {e}")
            return False
        except Exception as e:
            print(f"ExpressVPN authentication error: {e}")
            return False
    
    async def get_servers(self, country: str = None) -> List[ServerInfo]:
        """Get list of available ExpressVPN servers - GUI-only provider with static server list"""
        try:
            # ExpressVPN is GUI-only, provide a static list of popular servers
            # This would normally be retrieved from their API or GUI automation
            servers = []
            
            # Popular ExpressVPN server locations
            server_locations = [
                {"id": "usa-newyork", "name": "USA - New York", "country": "USA", "city": "New York"},
                {"id": "usa-losangeles", "name": "USA - Los Angeles", "country": "USA", "city": "Los Angeles"},
                {"id": "uk-london", "name": "UK - London", "country": "UK", "city": "London"},
                {"id": "germany-frankfurt", "name": "Germany - Frankfurt", "country": "Germany", "city": "Frankfurt"},
                {"id": "japan-tokyo", "name": "Japan - Tokyo", "country": "Japan", "city": "Tokyo"},
                {"id": "canada-toronto", "name": "Canada - Toronto", "country": "Canada", "city": "Toronto"},
                {"id": "australia-sydney", "name": "Australia - Sydney", "country": "Australia", "city": "Sydney"},
                {"id": "singapore", "name": "Singapore", "country": "Singapore", "city": "Singapore"},
                {"id": "netherlands-amsterdam", "name": "Netherlands - Amsterdam", "country": "Netherlands", "city": "Amsterdam"},
                {"id": "france-paris", "name": "France - Paris", "country": "France", "city": "Paris"}
            ]
            
            for server_data in server_locations:
                # Filter by country if specified
                if country and country.lower() not in server_data["country"].lower():
                    continue
                    
                server = ServerInfo(
                    id=server_data["id"],
                    name=server_data["name"],
                    country=server_data["country"],
                    city=server_data["city"],
                    ip_address="",  # ExpressVPN doesn't expose IPs
                    load=0,  # Not available via GUI
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.L2TP],
                    features=["High Speed", "Netflix", "Streaming Optimized"]
                )
                servers.append(server)
            
            print(f"ExpressVPN: Retrieved {len(servers)} servers (GUI-based provider)")
            return servers
                
        except Exception as e:
            print(f"ExpressVPN server list error: {e}")
            return []
    
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to ExpressVPN server - GUI-only provider"""
        try:
            # ExpressVPN is GUI-only, provide user guidance
            print(f"ExpressVPN: To connect to {server.name}, please:")
            print("1. Open ExpressVPN application")
            print("2. Select the desired server location")
            print("3. Click the connect button")
            print("Note: ExpressVPN connections are managed through the GUI")
            
            # Update status to indicate GUI connection required
            self.connection_info.status = ConnectionStatus.CONNECTING
            self.connection_info.server = server
            self.connection_info.protocol = protocol or ProtocolType.OPENVPN
            
            # Return True as the guidance has been provided
            return True
                
        except Exception as e:
            print(f"ExpressVPN connection error: {e}")
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
