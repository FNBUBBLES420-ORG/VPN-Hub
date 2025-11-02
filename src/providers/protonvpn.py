"""
ProtonVPN Provider Implementation - SECURITY HARDENED
Handles connections and management for ProtonVPN services with secure command execution
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

class ProtonVPNProvider(VPNProviderInterface):
    """ProtonVPN provider implementation with enhanced security and privacy focus"""
    
    def __init__(self, config: Dict):
        super().__init__("ProtonVPN", config)
        self.api_base = "https://api.protonvpn.ch"
        self.secure_executor = SecureCommandExecutor()
        self.client_config_path = config.get('config_path', '/usr/local/protonvpn-cli')
        
    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with ProtonVPN using secure command execution"""
        try:
            # Use secure authentication through SecureCommandExecutor
            success, message = await self.secure_executor.execute_vpn_auth(
                'protonvpn', username, password
            )
            
            if success:
                self.is_authenticated = True
                return True
            else:
                # Log sanitized error (no credentials exposed)
                user_hash = InputSanitizer.hash_sensitive_data(username)
                print(f"ProtonVPN authentication failed for user {user_hash}")
                return False
                
        except SecurityException as e:
            print(f"ProtonVPN authentication security error: {e}")
            return False
        except Exception as e:
            print(f"ProtonVPN authentication error: {e}")
            return False
    
    async def get_servers(self, country: str = None) -> List[ServerInfo]:
        """Get list of available ProtonVPN servers with privacy-focused features"""
        try:
            # Use secure command execution to get server list
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(['protonvpn-cli', 'status'])
            
            # If status command works, try to get server list
            if return_code == 0:
                return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(['protonvpn-cli', 'connect', '--help'])
                
                # Parse help output to get available servers/countries
                servers = []
                
                # ProtonVPN has different server tiers and features
                server_configs = [
                    # Free tier servers
                    {'id': 'JP-FREE#1', 'name': 'JP-FREE#1', 'country': 'Japan', 'city': 'Tokyo', 'tier': 'free'},
                    {'id': 'NL-FREE#1', 'name': 'NL-FREE#1', 'country': 'Netherlands', 'city': 'Amsterdam', 'tier': 'free'},
                    {'id': 'US-FREE#1', 'name': 'US-FREE#1', 'country': 'United States', 'city': 'New York', 'tier': 'free'},
                    
                    # Basic tier servers
                    {'id': 'CH#1', 'name': 'CH#1', 'country': 'Switzerland', 'city': 'Zurich', 'tier': 'basic'},
                    {'id': 'DE#1', 'name': 'DE#1', 'country': 'Germany', 'city': 'Frankfurt', 'tier': 'basic'},
                    {'id': 'UK#1', 'name': 'UK#1', 'country': 'United Kingdom', 'city': 'London', 'tier': 'basic'},
                    {'id': 'FR#1', 'name': 'FR#1', 'country': 'France', 'city': 'Paris', 'tier': 'basic'},
                    {'id': 'SE#1', 'name': 'SE#1', 'country': 'Sweden', 'city': 'Stockholm', 'tier': 'basic'},
                    {'id': 'NO#1', 'name': 'NO#1', 'country': 'Norway', 'city': 'Oslo', 'tier': 'basic'},
                    
                    # Plus tier servers (with P2P, Streaming)
                    {'id': 'US-CA#1', 'name': 'US-CA#1', 'country': 'United States', 'city': 'Los Angeles', 'tier': 'plus'},
                    {'id': 'CA#1', 'name': 'CA#1', 'country': 'Canada', 'city': 'Toronto', 'tier': 'plus'},
                    {'id': 'AU#1', 'name': 'AU#1', 'country': 'Australia', 'city': 'Sydney', 'tier': 'plus'},
                    {'id': 'SG#1', 'name': 'SG#1', 'country': 'Singapore', 'city': 'Singapore', 'tier': 'plus'},
                    
                    # Secure Core servers (extra security)
                    {'id': 'CH-US#1', 'name': 'CH-US#1', 'country': 'United States', 'city': 'New York', 'tier': 'secure_core'},
                    {'id': 'IS-US#1', 'name': 'IS-US#1', 'country': 'United States', 'city': 'Chicago', 'tier': 'secure_core'},
                    {'id': 'SE-UK#1', 'name': 'SE-UK#1', 'country': 'United Kingdom', 'city': 'London', 'tier': 'secure_core'},
                ]
                
                for server_config in server_configs:
                    # Filter by country if specified
                    if country and country.lower() not in server_config['country'].lower():
                        continue
                    
                    # Determine features based on tier
                    features = ['NetShield', 'Kill Switch', 'DNS Leak Protection']
                    if server_config['tier'] == 'plus':
                        features.extend(['P2P', 'Streaming', 'Tor'])
                    elif server_config['tier'] == 'secure_core':
                        features.extend(['Secure Core', 'Multi-hop', 'High Security'])
                    elif server_config['tier'] == 'free':
                        features = ['Basic Protection']
                    
                    server = ServerInfo(
                        id=server_config['id'],
                        name=server_config['name'],
                        country=server_config['country'],
                        city=server_config['city'],
                        ip_address=f"proton-{server_config['id'].lower().replace('#', '')}.servers.protonvpn.com",
                        load=0,  # ProtonVPN CLI doesn't provide load info directly
                        protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                        features=features
                    )
                    servers.append(server)
                
                return servers
            else:
                print(f"Failed to get ProtonVPN servers: {stderr}")
                return []
                
        except SecurityException as e:
            print(f"ProtonVPN get_servers security error: {e}")
            return []
        except Exception as e:
            print(f"Error getting ProtonVPN servers: {e}")
            return []
    
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to ProtonVPN server with enhanced privacy and security"""
        try:
            # Sanitize server name
            server_name = InputSanitizer.sanitize_server_name(server.name)
            
            # Map protocol type to ProtonVPN protocol string
            protocol_str = None
            if protocol == ProtocolType.OPENVPN:
                protocol_str = "openvpn"
            elif protocol == ProtocolType.IKEV2:
                protocol_str = "ikev2"
            elif protocol == ProtocolType.WIREGUARD:
                protocol_str = "wireguard"
            
            # Build connection command
            connect_args = ['protonvpn-cli', 'connect']
            
            # Add server specification
            if server_name:
                connect_args.append(server_name)
            
            # Add protocol if specified
            if protocol_str:
                connect_args.extend(['--protocol', protocol_str])
            
            # Add ProtonVPN security features
            connect_args.extend([
                '--kill-switch', 'on',  # Enable kill switch
                '--netshield', '2',     # Block malware and ads (highest level)
                '--dns-leak-protection', 'on',  # Prevent DNS leaks
                '--ipv6-leak-protection', 'on'  # Prevent IPv6 leaks
            ])
            
            # Use secure command execution
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(connect_args)
            
            if return_code == 0:
                self.connection_info.status = ConnectionStatus.CONNECTED
                self.connection_info.server = server
                self.connection_info.protocol = protocol
                return True
            else:
                print(f"ProtonVPN connection failed: {stderr}")
                self.connection_info.status = ConnectionStatus.ERROR
                return False
                
        except SecurityException as e:
            print(f"ProtonVPN connection security error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return False
        except Exception as e:
            print(f"ProtonVPN connection error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return False
    
    async def disconnect(self) -> bool:
        """Disconnect from ProtonVPN using secure execution"""
        try:
            # Use secure command execution
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(['protonvpn-cli', 'disconnect'])
            
            if return_code == 0:
                self.connection_info.status = ConnectionStatus.DISCONNECTED
                self.connection_info.server = None
                return True
            else:
                print(f"ProtonVPN disconnect failed: {stderr}")
                return False
                
        except SecurityException as e:
            print(f"ProtonVPN disconnect security error: {e}")
            return False
        except Exception as e:
            print(f"ProtonVPN disconnect error: {e}")
            return False
    
    async def get_connection_status(self) -> ConnectionInfo:
        """Get current ProtonVPN connection status with detailed security info"""
        try:
            # Use secure command execution
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(['protonvpn-cli', 'status'])
            
            if return_code == 0:
                output = stdout.lower()
                if "connected" in output or "active" in output:
                    self.connection_info.status = ConnectionStatus.CONNECTED
                    
                    # Parse detailed status information
                    lines = stdout.split('\n')
                    for line in lines:
                        line_lower = line.lower()
                        if "server:" in line_lower:
                            server_info = line.split(': ')[1] if ': ' in line else None
                            if server_info:
                                self.connection_info.server_name = server_info
                        elif "ip:" in line_lower or "current ip:" in line_lower:
                            ip_info = line.split(': ')[1] if ': ' in line else None
                            if ip_info:
                                self.connection_info.public_ip = ip_info
                        elif "protocol:" in line_lower:
                            protocol_info = line.split(': ')[1] if ': ' in line else None
                            if protocol_info:
                                # Map protocol string back to enum
                                if "openvpn" in protocol_info.lower():
                                    self.connection_info.protocol = ProtocolType.OPENVPN
                                elif "ikev2" in protocol_info.lower():
                                    self.connection_info.protocol = ProtocolType.IKEV2
                                elif "wireguard" in protocol_info.lower():
                                    self.connection_info.protocol = ProtocolType.WIREGUARD
                        elif "kill switch:" in line_lower:
                            self.connection_info.kill_switch = "enabled" in line_lower or "on" in line_lower
                        elif "netshield:" in line_lower:
                            self.connection_info.ad_block = "enabled" in line_lower or "on" in line_lower
                else:
                    self.connection_info.status = ConnectionStatus.DISCONNECTED
            else:
                self.connection_info.status = ConnectionStatus.ERROR
            
            return self.connection_info
            
        except SecurityException as e:
            print(f"ProtonVPN status security error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return self.connection_info
        except Exception as e:
            print(f"Error getting ProtonVPN status: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return self.connection_info
    
    async def get_public_ip(self) -> str:
        """Get current public IP address with privacy verification"""
        try:
            # Use ProtonVPN's own IP check service for consistency
            ip_services = [
                "https://api.protonvpn.ch/vpn/clientconfig",  # ProtonVPN's service
                "https://api.ipify.org?format=json",
                "https://httpbin.org/ip"
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
                                elif 'IP' in data:
                                    return data['IP']
                except:
                    continue
            
            return None
        except Exception as e:
            print(f"Error getting public IP: {e}")
            return None
    
    async def test_connection(self) -> Tuple[bool, float]:
        """Test ProtonVPN connection with privacy and security verification"""
        try:
            import time
            start_time = time.time()
            
            # Test with multiple endpoints for comprehensive check
            test_endpoints = [
                "https://www.google.com",
                "https://api.protonvpn.ch/test/ping",
                "https://1.1.1.1"  # Cloudflare DNS
            ]
            
            successful_tests = 0
            total_latency = 0
            
            for endpoint in test_endpoints:
                try:
                    test_start = time.time()
                    async with aiohttp.ClientSession() as session:
                        async with session.get(endpoint, timeout=10) as response:
                            if response.status == 200:
                                test_end = time.time()
                                test_latency = (test_end - test_start) * 1000
                                total_latency += test_latency
                                successful_tests += 1
                except:
                    continue
            
            if successful_tests > 0:
                average_latency = total_latency / successful_tests
                return True, average_latency
            else:
                return False, 0
                
        except Exception as e:
            print(f"Connection test failed: {e}")
            return False, 0
    
    async def get_supported_protocols(self) -> List[ProtocolType]:
        """Get supported protocols for ProtonVPN"""
        return [ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD]
    
    async def enable_secure_core(self) -> bool:
        """Enable ProtonVPN Secure Core for maximum privacy"""
        try:
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(
                ['protonvpn-cli', 'connect', '--sc']
            )
            return return_code == 0
        except Exception as e:
            print(f"Error enabling Secure Core: {e}")
            return False
    
    async def enable_netshield(self, level: int = 2) -> bool:
        """Enable NetShield ad/malware blocking (0=off, 1=malware, 2=malware+ads)"""
        try:
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(
                ['protonvpn-cli', 'netshield', '--set', str(level)]
            )
            return return_code == 0
        except Exception as e:
            print(f"Error enabling NetShield: {e}")
            return False
    
    async def enable_tor_support(self) -> bool:
        """Enable Tor over VPN for maximum anonymity"""
        try:
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(
                ['protonvpn-cli', 'connect', '--tor']
            )
            return return_code == 0
        except Exception as e:
            print(f"Error enabling Tor support: {e}")
            return False
    
    async def get_privacy_features(self) -> Dict[str, bool]:
        """Get current privacy and security features status"""
        try:
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(
                ['protonvpn-cli', 'status', '--json']
            )
            
            features = {
                'kill_switch': False,
                'dns_leak_protection': False,
                'ipv6_leak_protection': False,
                'netshield': False,
                'secure_core': False,
                'tor_support': False
            }
            
            if return_code == 0:
                try:
                    status_data = json.loads(stdout)
                    # Parse JSON status for feature information
                    features['kill_switch'] = status_data.get('killswitch', False)
                    features['netshield'] = status_data.get('netshield', 0) > 0
                    features['secure_core'] = status_data.get('secure_core', False)
                except json.JSONDecodeError:
                    # Fallback to text parsing
                    output = stdout.lower()
                    for feature in features.keys():
                        if f"{feature}: on" in output or f"{feature}: enabled" in output:
                            features[feature] = True
            
            return features
        except Exception as e:
            print(f"Error getting privacy features: {e}")
            return {}
    
    async def connect_fastest(self, tier: str = 'free') -> bool:
        """Connect to fastest available server in specified tier"""
        try:
            connect_args = ['protonvpn-cli', 'connect', '--fastest']
            
            # Add tier specification
            if tier == 'free':
                connect_args.append('--free')
            elif tier == 'plus':
                connect_args.append('--p2p')  # Plus tier supports P2P
            elif tier == 'secure_core':
                connect_args.append('--sc')
            
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(connect_args)
            
            if return_code == 0:
                self.connection_info.status = ConnectionStatus.CONNECTED
                return True
            else:
                print(f"ProtonVPN fastest connection failed: {stderr}")
                return False
                
        except Exception as e:
            print(f"Error connecting to fastest server: {e}")
            return False