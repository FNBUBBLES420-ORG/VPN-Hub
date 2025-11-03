"""
CyberGhost VPN Provider Implementation - SECURITY HARDENED
Handles connections and management for CyberGhost VPN services with secure command execution
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

class CyberGhostProvider(VPNProviderInterface):
    """CyberGhost VPN provider implementation with enhanced security and secure protocol implementation"""
    
    def __init__(self, config: Dict):
        super().__init__("CyberGhost", config)
        self.api_base = "https://api.cyberghost.com"
        self.secure_executor = SecureCommandExecutor()
        self.client_config_path = config.get('config_path', '/usr/local/cyberghost')
        
    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with CyberGhost using GUI application"""
        try:
            # CyberGhost Windows version uses GUI authentication
            success, message = await self.secure_executor.execute_vpn_auth(
                'cyberghost', username, password
            )
            
            if success:
                self.is_authenticated = True
                user_hash = InputSanitizer.hash_sensitive_data(username)
                print(f"CyberGhost: CyberGhost GUI launched. Please authenticate through the application.")
                return True
            else:
                # Log sanitized error (no credentials exposed)
                user_hash = InputSanitizer.hash_sensitive_data(username)
                print(f"CyberGhost authentication failed for user {user_hash}: {message}")
                return False
                
        except SecurityException as e:
            print(f"CyberGhost authentication security error: {e}")
            return False
        except Exception as e:
            print(f"CyberGhost authentication error: {e}")
            return False
    
    async def get_servers(self, country: str = None) -> List[ServerInfo]:
        """Get list of available CyberGhost servers (GUI-based provider)"""
        try:
            # CyberGhost GUI doesn't provide CLI server listing
            # Provide static server list based on common CyberGhost locations
            servers = [
                ServerInfo(
                    id="cg-us-newyork-001",
                    name="New York #1",
                    country="United States", 
                    city="New York",
                    ip_address="us-ny.cyberghost.com",
                    load=25,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                ),
                ServerInfo(
                    id="cg-us-losangeles-001",
                    name="Los Angeles #1", 
                    country="United States",
                    city="Los Angeles",
                    ip_address="us-la.cyberghost.com",
                    load=15,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                ),
                ServerInfo(
                    id="cg-uk-london-001",
                    name="London #1",
                    country="United Kingdom",
                    city="London", 
                    ip_address="uk-lon.cyberghost.com",
                    load=30,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                ),
                ServerInfo(
                    id="cg-de-berlin-001",
                    name="Berlin #1",
                    country="Germany",
                    city="Berlin",
                    ip_address="de-ber.cyberghost.com", 
                    load=20,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                ),
                ServerInfo(
                    id="cg-fr-paris-001", 
                    name="Paris #1",
                    country="France",
                    city="Paris",
                    ip_address="fr-par.cyberghost.com",
                    load=18,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                ),
                ServerInfo(
                    id="cg-nl-amsterdam-001",
                    name="Amsterdam #1", 
                    country="Netherlands",
                    city="Amsterdam",
                    ip_address="nl-ams.cyberghost.com",
                    load=22,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                ),
                ServerInfo(
                    id="cg-ca-toronto-001",
                    name="Toronto #1",
                    country="Canada", 
                    city="Toronto",
                    ip_address="ca-tor.cyberghost.com",
                    load=28,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                ),
                ServerInfo(
                    id="cg-au-sydney-001",
                    name="Sydney #1",
                    country="Australia",
                    city="Sydney",
                    ip_address="au-syd.cyberghost.com",
                    load=35,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                ),
                ServerInfo(
                    id="cg-jp-tokyo-001",
                    name="Tokyo #1", 
                    country="Japan",
                    city="Tokyo",
                    ip_address="jp-tok.cyberghost.com",
                    load=32,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                ),
                ServerInfo(
                    id="cg-sg-singapore-001",
                    name="Singapore #1",
                    country="Singapore",
                    city="Singapore", 
                    ip_address="sg-sin.cyberghost.com",
                    load=26,
                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                    features=['NoSpy', 'P2P', 'Streaming']
                )
            ]
            
            # Filter by country if specified
            if country:
                servers = [s for s in servers if country.lower() in s.country.lower()]
            
            print(f"CyberGhost: Retrieved {len(servers)} servers (GUI-based provider)")
            return servers
                
        except Exception as e:
            print(f"Error getting CyberGhost servers: {e}")
            return []
    
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to CyberGhost server using GUI application"""
        try:
            # CyberGhost GUI-based connection
            # User needs to manually connect through the CyberGhost application
            print(f"CyberGhost: To connect to {server.name} ({server.country}):")
            print("1. Open CyberGhost application")
            print("2. Navigate to server list")
            print(f"3. Select {server.country} -> {server.city}")
            print("4. Click Connect")
            
            if protocol:
                protocol_map = {
                    ProtocolType.OPENVPN: "OpenVPN",
                    ProtocolType.IKEV2: "IKEv2", 
                    ProtocolType.WIREGUARD: "WireGuard"
                }
                protocol_name = protocol_map.get(protocol, "Auto")
                print(f"5. Recommended protocol: {protocol_name}")
            
            # Update connection info for GUI tracking
            self.connection_info.status = ConnectionStatus.CONNECTING
            self.connection_info.server = server
            self.connection_info.protocol = protocol
            
            print("CyberGhost: Connection initiated via GUI. Please complete in CyberGhost application.")
            return True
                
        except Exception as e:
            print(f"CyberGhost connection error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from CyberGhost using secure execution"""
        try:
            # Use secure command execution
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(['cyberghost-vpn', '--stop'])
            
            if return_code == 0:
                self.connection_info.status = ConnectionStatus.DISCONNECTED
                self.connection_info.server = None
                return True
            else:
                print(f"CyberGhost disconnect failed: {stderr}")
                return False
                
        except SecurityException as e:
            print(f"CyberGhost disconnect security error: {e}")
            return False
        except Exception as e:
            print(f"CyberGhost disconnect error: {e}")
            return False
    
    async def get_connection_status(self) -> ConnectionInfo:
        """Get current CyberGhost connection status using secure execution"""
        try:
            # Use secure command execution
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(['cyberghost-vpn', '--status'])
            
            if return_code == 0:
                output = stdout.lower()
                if "connected" in output or "active" in output:
                    self.connection_info.status = ConnectionStatus.CONNECTED
                    
                    # Parse additional info from status output
                    lines = stdout.split('\n')
                    for line in lines:
                        if "server:" in line.lower():
                            server_info = line.split(': ')[1] if ': ' in line else None
                            if server_info:
                                self.connection_info.server_name = server_info
                        elif "ip:" in line.lower() or "public ip:" in line.lower():
                            ip_info = line.split(': ')[1] if ': ' in line else None
                            if ip_info:
                                self.connection_info.public_ip = ip_info
                        elif "protocol:" in line.lower():
                            protocol_info = line.split(': ')[1] if ': ' in line else None
                            if protocol_info:
                                # Map protocol string back to enum
                                if "openvpn" in protocol_info.lower():
                                    self.connection_info.protocol = ProtocolType.OPENVPN
                                elif "ikev2" in protocol_info.lower():
                                    self.connection_info.protocol = ProtocolType.IKEV2
                                elif "wireguard" in protocol_info.lower():
                                    self.connection_info.protocol = ProtocolType.WIREGUARD
                else:
                    self.connection_info.status = ConnectionStatus.DISCONNECTED
            else:
                self.connection_info.status = ConnectionStatus.ERROR
            
            return self.connection_info
            
        except SecurityException as e:
            print(f"CyberGhost status security error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return self.connection_info
        except Exception as e:
            print(f"Error getting CyberGhost status: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return self.connection_info
    
    async def get_public_ip(self) -> str:
        """Get current public IP address with enhanced security"""
        try:
            # Use multiple IP services for verification
            ip_services = [
                "https://api.ipify.org?format=json",
                "https://httpbin.org/ip",
                "https://api.myip.com"
            ]
            
            for service in ip_services:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(service, timeout=10) as response:
                            if response.status == 200:
                                data = await response.json()
                                # Handle different response formats
                                if 'ip' in data:
                                    return data['ip']
                                elif 'origin' in data:
                                    return data['origin']
                                elif 'ip_address' in data:
                                    return data['ip_address']
                except:
                    continue
            
            return None
        except Exception as e:
            print(f"Error getting public IP: {e}")
            return None
    
    async def test_connection(self) -> Tuple[bool, float]:
        """Test CyberGhost connection speed and security"""
        try:
            import time
            start_time = time.time()
            
            # Test with HTTPS endpoint for security
            async with aiohttp.ClientSession() as session:
                async with session.get("https://www.google.com", timeout=10) as response:
                    if response.status == 200:
                        end_time = time.time()
                        latency = (end_time - start_time) * 1000  # Convert to milliseconds
                        
                        # Additional security check - verify HTTPS
                        if str(response.url).startswith('https://'):
                            return True, latency
                        else:
                            print("Warning: Connection not using HTTPS")
                            return False, 0
            return False, 0
        except Exception as e:
            print(f"Connection test failed: {e}")
            return False, 0
    
    async def get_supported_protocols(self) -> List[ProtocolType]:
        """Get supported protocols for CyberGhost with secure implementation"""
        return [ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD]
    
    async def enable_kill_switch(self) -> bool:
        """Enable CyberGhost kill switch for enhanced security"""
        try:
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(
                ['cyberghost-vpn', '--set', 'kill-switch', 'on']
            )
            return return_code == 0
        except Exception as e:
            print(f"Error enabling kill switch: {e}")
            return False
    
    async def enable_dns_leak_protection(self) -> bool:
        """Enable DNS leak protection for secure protocol implementation"""
        try:
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(
                ['cyberghost-vpn', '--set', 'dns-leak-protection', 'on']
            )
            return return_code == 0
        except Exception as e:
            print(f"Error enabling DNS leak protection: {e}")
            return False
    
    async def get_security_features(self) -> Dict[str, bool]:
        """Get current security features status"""
        try:
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(
                ['cyberghost-vpn', '--security-status']
            )
            
            features = {
                'kill_switch': False,
                'dns_leak_protection': False,
                'auto_https': False,
                'malware_blocking': False,
                'ad_blocking': False
            }
            
            if return_code == 0:
                output = stdout.lower()
                for feature in features.keys():
                    if f"{feature}: on" in output or f"{feature}: enabled" in output:
                        features[feature] = True
            
            return features
        except Exception as e:
            print(f"Error getting security features: {e}")
            return {}
