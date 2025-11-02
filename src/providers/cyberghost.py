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
        """Authenticate with CyberGhost using secure command execution"""
        try:
            # Use secure authentication through SecureCommandExecutor
            success, message = await self.secure_executor.execute_vpn_auth(
                'cyberghost-vpn', username, password
            )
            
            if success:
                self.is_authenticated = True
                return True
            else:
                # Log sanitized error (no credentials exposed)
                user_hash = InputSanitizer.hash_sensitive_data(username)
                print(f"CyberGhost authentication failed for user {user_hash}")
                return False
                
        except SecurityException as e:
            print(f"CyberGhost authentication security error: {e}")
            return False
        except Exception as e:
            print(f"CyberGhost authentication error: {e}")
            return False
    
    async def get_servers(self, country: str = None) -> List[ServerInfo]:
        """Get list of available CyberGhost servers with secure protocol implementation"""
        try:
            # Use secure command execution to get server list
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(['cyberghost-vpn', '--server-list'])
            
            if return_code == 0:
                servers = []
                lines = stdout.split('\n')
                
                for line in lines:
                    if line.strip() and 'Server' in line:
                        # Parse CyberGhost server format: "Server: country-city-number (IP)"
                        parts = line.split()
                        if len(parts) >= 3:
                            server_name = parts[1]
                            ip_match = None
                            
                            # Extract IP from parentheses
                            if '(' in line and ')' in line:
                                ip_start = line.find('(') + 1
                                ip_end = line.find(')')
                                ip_match = line[ip_start:ip_end]
                            
                            # Parse server name to extract location info
                            name_parts = server_name.split('-')
                            if len(name_parts) >= 2:
                                country_code = name_parts[0].upper()
                                city = name_parts[1].title()
                                
                                # Map country codes to full names
                                country_map = {
                                    'US': 'United States', 'UK': 'United Kingdom', 'DE': 'Germany',
                                    'FR': 'France', 'NL': 'Netherlands', 'CA': 'Canada',
                                    'AU': 'Australia', 'JP': 'Japan', 'SG': 'Singapore',
                                    'CH': 'Switzerland', 'SE': 'Sweden', 'NO': 'Norway'
                                }
                                
                                full_country = country_map.get(country_code, country_code)
                                
                                # Filter by country if specified
                                if country and country.lower() not in full_country.lower():
                                    continue
                                
                                server = ServerInfo(
                                    id=server_name,
                                    name=server_name,
                                    country=full_country,
                                    city=city,
                                    ip_address=ip_match or f"cg-{server_name}.servers.cyberghost.com",
                                    load=0,  # CyberGhost doesn't provide load info via CLI
                                    protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                                    features=['NoSpy', 'P2P', 'Streaming', 'Dedicated IP']
                                )
                                servers.append(server)
                
                return servers
            else:
                print(f"Failed to get CyberGhost servers: {stderr}")
                return []
                
        except SecurityException as e:
            print(f"CyberGhost get_servers security error: {e}")
            return []
        except Exception as e:
            print(f"Error getting CyberGhost servers: {e}")
            return []
    
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to CyberGhost server using secure protocol implementation"""
        try:
            # Sanitize server name
            server_name = InputSanitizer.sanitize_server_name(server.name)
            
            # Map protocol type to CyberGhost protocol string
            protocol_str = None
            if protocol == ProtocolType.OPENVPN:
                protocol_str = "openvpn"
            elif protocol == ProtocolType.IKEV2:
                protocol_str = "ikev2"
            elif protocol == ProtocolType.WIREGUARD:
                protocol_str = "wireguard"
            
            # Build connection command with secure protocol options
            connect_args = ['cyberghost-vpn', '--connect']
            if server_name:
                connect_args.extend(['--server', server_name])
            if protocol_str:
                connect_args.extend(['--protocol', protocol_str])
            
            # Add security-enhanced connection options
            connect_args.extend([
                '--kill-switch', 'on',  # Enable kill switch for security
                '--dns-leak-protection', 'on',  # Prevent DNS leaks
                '--auto-https', 'on',  # Force HTTPS when possible
                '--block-malicious', 'on'  # Block malicious websites
            ])
            
            # Use secure command execution
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(connect_args)
            
            if return_code == 0:
                self.connection_info.status = ConnectionStatus.CONNECTED
                self.connection_info.server = server
                self.connection_info.protocol = protocol
                return True
            else:
                print(f"CyberGhost connection failed: {stderr}")
                self.connection_info.status = ConnectionStatus.ERROR
                return False
                
        except SecurityException as e:
            print(f"CyberGhost connection security error: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return False
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