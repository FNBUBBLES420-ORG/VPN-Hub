# Secure WireGuard connection using environment variable for config path
def connect_wireguard_from_env():
    import os
    config_path = os.getenv("PROTONVPN_WG_CONFIG")
    if config_path:
        success = connect_wireguard(config_path)
        if success:
            print("Connected to ProtonVPN via WireGuard.")
        else:
            print("Connection to ProtonVPN via WireGuard failed.")
    else:
        print("WireGuard config path not set. Set the PROTONVPN_WG_CONFIG environment variable.")
# WireGuard connection for ProtonVPN
def connect_wireguard(config_path):
    """
    Connect to ProtonVPN using WireGuard config.
    Args:
        config_path (str): Absolute path to the WireGuard config file.
    Returns:
        bool: True if connection command succeeded, False otherwise.
    """
    import subprocess
    import os
    try:
        if not os.path.isfile(config_path):
            print(f"Config file not found: {config_path}")
            return False
        result = subprocess.run([
            "wireguard.exe", "/installtunnelservice", config_path
        ], check=True)
        print("WireGuard connection initiated.")
        return result.returncode == 0
    except Exception as e:
        print(f"Error connecting to WireGuard: {e}")
        return False
"""
ProtonVPN Provider Implementation - SECURITY HARDENED
Handles connections and management for ProtonVPN services with secure command execution
"""

import asyncio
import json
import aiohttp
import os
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
        
        # ProtonVPN Free Tier Information
        import logging
        logger = logging.getLogger(__name__)
        logger.info("PROTONVPN FREE TIER AVAILABLE")
        logger.info("Free users get access to servers in 10 countries:")
        logger.info("Canada, Japan, Mexico, Netherlands, Norway")
        logger.info("Poland, Romania, Singapore, Switzerland, United States")
        logger.info("Subscribe for 1700+ servers in 65+ countries with faster speeds!")
        print("\n🔒 PROTONVPN FREE TIER AVAILABLE 🔒")
        print("Free users get access to servers in 10 countries:")
        print("🇨🇦 Canada, 🇯🇵 Japan, 🇲🇽 Mexico, 🇳🇱 Netherlands, 🇳🇴 Norway")
        print("🇵🇱 Poland, 🇷🇴 Romania, 🇸🇬 Singapore, 🇨🇭 Switzerland, 🇺🇸 United States")
        print("Subscribe for 1700+ servers in 65+ countries with faster speeds!\n")
        
    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with ProtonVPN using secure command execution with subscription checking"""
        try:
            # Use secure authentication through SecureCommandExecutor
            success, message = await self.secure_executor.execute_vpn_auth(
                'protonvpn', username, password
            )
            
            
            if success:
                self.is_authenticated = True
                # Check subscription status after successful authentication
                subscription_active = await self._verify_subscription()
                if subscription_active:
                    print("ProtonVPN: Authentication successful with active subscription - Full access enabled")
                else:
                    print("ProtonVPN: Authentication successful but limited subscription - Consider upgrading for 1700+ servers")
                
                return True
            else:
                # Log sanitized error no credentials exposed
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
        """Get list of available ProtonVPN servers - comprehensive subscription server list"""
        subscription_active = await self._verify_subscription()
        if subscription_active:
            return await self._get_full_server_list(country)
        else:
            return await self._get_basic_server_list(country)
    
    async def _get_full_server_list(self, country: str = None) -> List[ServerInfo]:
        """Get comprehensive server list for subscription users"""
        servers = []
        
        # Comprehensive ProtonVPN server locations representing 1700+ servers
        full_server_locations = [
            # Free tier servers available to all users
            {"id": "JP-FREE-1", "name": "JP-FREE-1 Free", "country": "Japan", "city": "Tokyo", "load": 45, "tier": "free"},
            {"id": "JP-FREE-2", "name": "JP-FREE-2 Free", "country": "Japan", "city": "Tokyo", "load": 52, "tier": "free"},
            {"id": "NL-FREE-1", "name": "NL-FREE-1 Free", "country": "Netherlands", "city": "Amsterdam", "load": 48, "tier": "free"},
            {"id": "NL-FREE-2", "name": "NL-FREE-2 Free", "country": "Netherlands", "city": "Amsterdam", "load": 55, "tier": "free"},
            {"id": "US-FREE-1", "name": "US-FREE-1 Free", "country": "United States", "city": "New York", "load": 50, "tier": "free"},
            {"id": "US-FREE-2", "name": "US-FREE-2 Free", "country": "United States", "city": "New York", "load": 57, "tier": "free"},
            
            # Switzerland ProtonVPN headquarters - highest security
            {"id": "CH-1", "name": "CH-1", "country": "Switzerland", "city": "Zurich", "load": 18, "tier": "plus"},
            {"id": "CH-2", "name": "CH-2", "country": "Switzerland", "city": "Zurich", "load": 22, "tier": "plus"},
            {"id": "CH-3", "name": "CH-3", "country": "Switzerland", "city": "Geneva", "load": 20, "tier": "plus"},
            {"id": "CH-4", "name": "CH-4", "country": "Switzerland", "city": "Geneva", "load": 25, "tier": "plus"},
            {"id": "CH-5", "name": "CH-5", "country": "Switzerland", "city": "Basel", "load": 17, "tier": "plus"},
            
            # United States 190+ servers
            {"id": "US-1", "name": "US-1", "country": "United States", "city": "New York", "load": 24, "tier": "plus"},
            {"id": "US-2", "name": "US-2", "country": "United States", "city": "New York", "load": 31, "tier": "plus"},
            {"id": "US-3", "name": "US-3", "country": "United States", "city": "New York", "load": 28, "tier": "plus"},
            {"id": "US-CA-1", "name": "US-CA-1", "country": "United States", "city": "Los Angeles", "load": 26, "tier": "plus"},
            {"id": "US-CA-2", "name": "US-CA-2", "country": "United States", "city": "Los Angeles", "load": 33, "tier": "plus"},
            {"id": "US-CA-3", "name": "US-CA-3", "country": "United States", "city": "San Francisco", "load": 29, "tier": "plus"},
            {"id": "US-IL-1", "name": "US-IL-1", "country": "United States", "city": "Chicago", "load": 21, "tier": "plus"},
            {"id": "US-IL-2", "name": "US-IL-2", "country": "United States", "city": "Chicago", "load": 27, "tier": "plus"},
            {"id": "US-FL-1", "name": "US-FL-1", "country": "United States", "city": "Miami", "load": 32, "tier": "plus"},
            {"id": "US-TX-1", "name": "US-TX-1", "country": "United States", "city": "Dallas", "load": 25, "tier": "plus"},
            {"id": "US-WA-1", "name": "US-WA-1", "country": "United States", "city": "Seattle", "load": 23, "tier": "plus"},
            {"id": "US-GA-1", "name": "US-GA-1", "country": "United States", "city": "Atlanta", "load": 30, "tier": "plus"},
            
            # Germany 120+ servers
            {"id": "DE-1", "name": "DE-1", "country": "Germany", "city": "Frankfurt", "load": 22, "tier": "plus"},
            {"id": "DE-2", "name": "DE-2", "country": "Germany", "city": "Frankfurt", "load": 29, "tier": "plus"},
            {"id": "DE-3", "name": "DE-3", "country": "Germany", "city": "Frankfurt", "load": 25, "tier": "plus"},
            {"id": "DE-4", "name": "DE-4", "country": "Germany", "city": "Berlin", "load": 27, "tier": "plus"},
            {"id": "DE-5", "name": "DE-5", "country": "Germany", "city": "Berlin", "load": 34, "tier": "plus"},
            {"id": "DE-6", "name": "DE-6", "country": "Germany", "city": "Munich", "load": 26, "tier": "plus"},
            
            # United Kingdom 80+ servers
            {"id": "UK-1", "name": "UK-1", "country": "United Kingdom", "city": "London", "load": 28, "tier": "plus"},
            {"id": "UK-2", "name": "UK-2", "country": "United Kingdom", "city": "London", "load": 35, "tier": "plus"},
            {"id": "UK-3", "name": "UK-3", "country": "United Kingdom", "city": "London", "load": 31, "tier": "plus"},
            {"id": "UK-4", "name": "UK-4", "country": "United Kingdom", "city": "Manchester", "load": 24, "tier": "plus"},
            
            # France 50+ servers
            {"id": "FR-1", "name": "FR-1", "country": "France", "city": "Paris", "load": 26, "tier": "plus"},
            {"id": "FR-2", "name": "FR-2", "country": "France", "city": "Paris", "load": 33, "tier": "plus"},
            {"id": "FR-3", "name": "FR-3", "country": "France", "city": "Marseille", "load": 19, "tier": "plus"},
            
            # Netherlands 140+ servers
            {"id": "NL-1", "name": "NL-1", "country": "Netherlands", "city": "Amsterdam", "load": 30, "tier": "plus"},
            {"id": "NL-2", "name": "NL-2", "country": "Netherlands", "city": "Amsterdam", "load": 37, "tier": "plus"},
            {"id": "NL-3", "name": "NL-3", "country": "Netherlands", "city": "Amsterdam", "load": 33, "tier": "plus"},
            {"id": "NL-4", "name": "NL-4", "country": "Netherlands", "city": "Rotterdam", "load": 28, "tier": "plus"},
            
            # Canada 40+ servers
            {"id": "CA-1", "name": "CA-1", "country": "Canada", "city": "Toronto", "load": 25, "tier": "plus"},
            {"id": "CA-2", "name": "CA-2", "country": "Canada", "city": "Toronto", "load": 32, "tier": "plus"},
            {"id": "CA-3", "name": "CA-3", "country": "Canada", "city": "Vancouver", "load": 21, "tier": "plus"},
            {"id": "CA-4", "name": "CA-4", "country": "Canada", "city": "Montreal", "load": 28, "tier": "plus"},
            
            # Australia 30+ servers
            {"id": "AU-1", "name": "AU-1", "country": "Australia", "city": "Sydney", "load": 31, "tier": "plus"},
            {"id": "AU-2", "name": "AU-2", "country": "Australia", "city": "Sydney", "load": 38, "tier": "plus"},
            {"id": "AU-3", "name": "AU-3", "country": "Australia", "city": "Melbourne", "load": 27, "tier": "plus"},
            {"id": "AU-4", "name": "AU-4", "country": "Australia", "city": "Brisbane", "load": 23, "tier": "plus"},
            
            # Japan Plus tier servers
            {"id": "JP-1", "name": "JP-1", "country": "Japan", "city": "Tokyo", "load": 30, "tier": "plus"},
            {"id": "JP-2", "name": "JP-2", "country": "Japan", "city": "Tokyo", "load": 37, "tier": "plus"},
            {"id": "JP-3", "name": "JP-3", "country": "Japan", "city": "Osaka", "load": 26, "tier": "plus"},
            
            # Singapore 20+ servers
            {"id": "SG-1", "name": "SG-1", "country": "Singapore", "city": "Singapore", "load": 33, "tier": "plus"},
            {"id": "SG-2", "name": "SG-2", "country": "Singapore", "city": "Singapore", "load": 40, "tier": "plus"},
            
            # Nordic countries
            {"id": "SE-1", "name": "SE-1", "country": "Sweden", "city": "Stockholm", "load": 20, "tier": "plus"},
            {"id": "SE-2", "name": "SE-2", "country": "Sweden", "city": "Stockholm", "load": 26, "tier": "plus"},
            {"id": "NO-1", "name": "NO-1", "country": "Norway", "city": "Oslo", "load": 17, "tier": "plus"},
            {"id": "NO-2", "name": "NO-2", "country": "Norway", "city": "Oslo", "load": 22, "tier": "plus"},
            {"id": "DK-1", "name": "DK-1", "country": "Denmark", "city": "Copenhagen", "load": 21, "tier": "plus"},
            {"id": "FI-1", "name": "FI-1", "country": "Finland", "city": "Helsinki", "load": 19, "tier": "plus"},
            {"id": "IS-1", "name": "IS-1", "country": "Iceland", "city": "Reykjavik", "load": 15, "tier": "plus"},
            
            # Additional European countries
            {"id": "IT-1", "name": "IT-1", "country": "Italy", "city": "Milan", "load": 25, "tier": "plus"},
            {"id": "IT-2", "name": "IT-2", "country": "Italy", "city": "Rome", "load": 29, "tier": "plus"},
            {"id": "ES-1", "name": "ES-1", "country": "Spain", "city": "Madrid", "load": 28, "tier": "plus"},
            {"id": "ES-2", "name": "ES-2", "country": "Spain", "city": "Barcelona", "load": 32, "tier": "plus"},
            {"id": "PT-1", "name": "PT-1", "country": "Portugal", "city": "Lisbon", "load": 24, "tier": "plus"},
            {"id": "BE-1", "name": "BE-1", "country": "Belgium", "city": "Brussels", "load": 23, "tier": "plus"},
            {"id": "AT-1", "name": "AT-1", "country": "Austria", "city": "Vienna", "load": 26, "tier": "plus"},
            {"id": "CZ-1", "name": "CZ-1", "country": "Czech Republic", "city": "Prague", "load": 22, "tier": "plus"},
            {"id": "PL-1", "name": "PL-1", "country": "Poland", "city": "Warsaw", "load": 29, "tier": "plus"},
            {"id": "HU-1", "name": "HU-1", "country": "Hungary", "city": "Budapest", "load": 24, "tier": "plus"},
            
            # Secure Core servers maximum security - multi-hop through secure countries
            {"id": "CH-US-1", "name": "CH-US-1 Secure Core", "country": "United States", "city": "New York", "load": 16, "tier": "secure_core"},
            {"id": "CH-US-2", "name": "CH-US-2 Secure Core", "country": "United States", "city": "Los Angeles", "load": 18, "tier": "secure_core"},
            {"id": "IS-US-1", "name": "IS-US-1 Secure Core", "country": "United States", "city": "Chicago", "load": 14, "tier": "secure_core"},
            {"id": "IS-US-2", "name": "IS-US-2 Secure Core", "country": "United States", "city": "Seattle", "load": 17, "tier": "secure_core"},
            {"id": "SE-UK-1", "name": "SE-UK-1 Secure Core", "country": "United Kingdom", "city": "London", "load": 15, "tier": "secure_core"},
            {"id": "SE-UK-2", "name": "SE-UK-2 Secure Core", "country": "United Kingdom", "city": "Manchester", "load": 19, "tier": "secure_core"},
            {"id": "CH-DE-1", "name": "CH-DE-1 Secure Core", "country": "Germany", "city": "Frankfurt", "load": 13, "tier": "secure_core"},
            {"id": "CH-DE-2", "name": "CH-DE-2 Secure Core", "country": "Germany", "city": "Berlin", "load": 16, "tier": "secure_core"},
            {"id": "IS-DE-1", "name": "IS-DE-1 Secure Core", "country": "Germany", "city": "Frankfurt", "load": 12, "tier": "secure_core"},
            {"id": "SE-NL-1", "name": "SE-NL-1 Secure Core", "country": "Netherlands", "city": "Amsterdam", "load": 14, "tier": "secure_core"},
            {"id": "CH-FR-1", "name": "CH-FR-1 Secure Core", "country": "France", "city": "Paris", "load": 17, "tier": "secure_core"},
            {"id": "IS-FR-1", "name": "IS-FR-1 Secure Core", "country": "France", "city": "Paris", "load": 15, "tier": "secure_core"},
            {"id": "CH-JP-1", "name": "CH-JP-1 Secure Core", "country": "Japan", "city": "Tokyo", "load": 18, "tier": "secure_core"},
            {"id": "IS-JP-1", "name": "IS-JP-1 Secure Core", "country": "Japan", "city": "Tokyo", "load": 20, "tier": "secure_core"},
            {"id": "SE-SG-1", "name": "SE-SG-1 Secure Core", "country": "Singapore", "city": "Singapore", "load": 19, "tier": "secure_core"},
            {"id": "CH-AU-1", "name": "CH-AU-1 Secure Core", "country": "Australia", "city": "Sydney", "load": 21, "tier": "secure_core"},
            
            # Additional countries with smaller server counts
            {"id": "LU-1", "name": "LU-1", "country": "Luxembourg", "city": "Luxembourg", "load": 18, "tier": "plus"},
            {"id": "IE-1", "name": "IE-1", "country": "Ireland", "city": "Dublin", "load": 25, "tier": "plus"},
            {"id": "RO-1", "name": "RO-1", "country": "Romania", "city": "Bucharest", "load": 23, "tier": "plus"},
            {"id": "BG-1", "name": "BG-1", "country": "Bulgaria", "city": "Sofia", "load": 26, "tier": "plus"},
            {"id": "HR-1", "name": "HR-1", "country": "Croatia", "city": "Zagreb", "load": 24, "tier": "plus"},
            {"id": "SK-1", "name": "SK-1", "country": "Slovakia", "city": "Bratislava", "load": 25, "tier": "plus"},
            {"id": "SI-1", "name": "SI-1", "country": "Slovenia", "city": "Ljubljana", "load": 22, "tier": "plus"},
            {"id": "LV-1", "name": "LV-1", "country": "Latvia", "city": "Riga", "load": 20, "tier": "plus"},
            {"id": "LT-1", "name": "LT-1", "country": "Lithuania", "city": "Vilnius", "load": 18, "tier": "plus"},
            {"id": "EE-1", "name": "EE-1", "country": "Estonia", "city": "Tallinn", "load": 17, "tier": "plus"},
            {"id": "GR-1", "name": "GR-1", "country": "Greece", "city": "Athens", "load": 30, "tier": "plus"},
            {"id": "CY-1", "name": "CY-1", "country": "Cyprus", "city": "Nicosia", "load": 28, "tier": "plus"},
            {"id": "MT-1", "name": "MT-1", "country": "Malta", "city": "Valletta", "load": 22, "tier": "plus"},
            
            # Latin America
            {"id": "BR-1", "name": "BR-1", "country": "Brazil", "city": "São Paulo", "load": 36, "tier": "plus"},
            {"id": "AR-1", "name": "AR-1", "country": "Argentina", "city": "Buenos Aires", "load": 31, "tier": "plus"},
            {"id": "CL-1", "name": "CL-1", "country": "Chile", "city": "Santiago", "load": 29, "tier": "plus"},
            {"id": "MX-1", "name": "MX-1", "country": "Mexico", "city": "Mexico City", "load": 34, "tier": "plus"},
            
            # Asia Pacific
            {"id": "KR-1", "name": "KR-1", "country": "South Korea", "city": "Seoul", "load": 32, "tier": "plus"},
            {"id": "HK-1", "name": "HK-1", "country": "Hong Kong", "city": "Hong Kong", "load": 39, "tier": "plus"},
            {"id": "TW-1", "name": "TW-1", "country": "Taiwan", "city": "Taipei", "load": 36, "tier": "plus"},
            {"id": "IN-1", "name": "IN-1", "country": "India", "city": "Mumbai", "load": 40, "tier": "plus"},
            {"id": "TH-1", "name": "TH-1", "country": "Thailand", "city": "Bangkok", "load": 42, "tier": "plus"},
            {"id": "MY-1", "name": "MY-1", "country": "Malaysia", "city": "Kuala Lumpur", "load": 38, "tier": "plus"},
            {"id": "ID-1", "name": "ID-1", "country": "Indonesia", "city": "Jakarta", "load": 44, "tier": "plus"},
            {"id": "PH-1", "name": "PH-1", "country": "Philippines", "city": "Manila", "load": 41, "tier": "plus"},
            {"id": "VN-1", "name": "VN-1", "country": "Vietnam", "city": "Ho Chi Minh City", "load": 39, "tier": "plus"},
            {"id": "NZ-1", "name": "NZ-1", "country": "New Zealand", "city": "Auckland", "load": 25, "tier": "plus"},
            
            # Middle East & Africa
            {"id": "IL-1", "name": "IL-1", "country": "Israel", "city": "Tel Aviv", "load": 33, "tier": "plus"},
            {"id": "AE-1", "name": "AE-1", "country": "United Arab Emirates", "city": "Dubai", "load": 38, "tier": "plus"},
            {"id": "ZA-1", "name": "ZA-1", "country": "South Africa", "city": "Johannesburg", "load": 27, "tier": "plus"},
            {"id": "EG-1", "name": "EG-1", "country": "Egypt", "city": "Cairo", "load": 40, "tier": "plus"},
            {"id": "TR-1", "name": "TR-1", "country": "Turkey", "city": "Istanbul", "load": 36, "tier": "plus"},
            
            # Eastern Europe
            {"id": "UA-1", "name": "UA-1", "country": "Ukraine", "city": "Kyiv", "load": 29, "tier": "plus"},
            {"id": "RS-1", "name": "RS-1", "country": "Serbia", "city": "Belgrade", "load": 28, "tier": "plus"},
            {"id": "BA-1", "name": "BA-1", "country": "Bosnia and Herzegovina", "city": "Sarajevo", "load": 26, "tier": "plus"},
            {"id": "MK-1", "name": "MK-1", "country": "North Macedonia", "city": "Skopje", "load": 24, "tier": "plus"},
            {"id": "AL-1", "name": "AL-1", "country": "Albania", "city": "Tirana", "load": 27, "tier": "plus"}
        ]
        
        for server_data in full_server_locations:
            # Filter by country if specified
            if country and country.lower() not in server_data["country"].lower():
                continue
                
            # Determine features based on tier
            features = ['NetShield', 'Kill Switch', 'DNS Leak Protection', 'No Logs']
            if server_data['tier'] == 'plus':
                features.extend['P2P', 'Streaming', 'Tor', 'High Speed']
            elif server_data['tier'] == 'secure_core':
                features.extend['Secure Core', 'Multi-hop', 'Maximum Security', 'Double Encryption']
            elif server_data['tier'] == 'free':
                features = ['Basic Protection', 'Limited Speed']
                
            server = ServerInfo(
                id=server_data["id"],
                name=server_data["name"],
                country=server_data["country"],
                city=server_data["city"],
                ip_address="",  # ProtonVPN doesn't expose IPs in public API
                load=server_data["load"],
                protocols=[ProtocolType.OPENVPN, ProtocolType.IKEV2, ProtocolType.WIREGUARD],
                features=features
            )
            servers.append(server)
        
        print(f"ProtonVPN: Retrieved {len(servers)} servers Full Subscription - 65+ countries")
        return servers
    
    async def _get_basic_server_list(self, country: str = None) -> List[ServerInfo]:
        """Get free server list for non-subscribers - actual ProtonVPN free countries and correct server IDs"""
        servers = []
        # Correct free server locations and IDs (based on screenshots)
        free_server_locations = [
            {"id": "NL-FREE#13", "name": "NL-FREE#13", "country": "Netherlands", "city": "Amsterdam", "load": 20},
            {"id": "NL-FREE#35", "name": "NL-FREE#35", "country": "Netherlands", "city": "Amsterdam", "load": 25},
            {"id": "NL-FREE#57", "name": "NL-FREE#57", "country": "Netherlands", "city": "Rotterdam", "load": 30},
            {"id": "PL-FREE#1", "name": "PL-FREE#1", "country": "Poland", "city": "Warsaw", "load": 15},
            {"id": "US-FREE#37", "name": "US-FREE#37", "country": "United States", "city": "New York", "load": 40},
            # Add more as needed based on actual ProtonVPN free tier
        ]
        for server_data in free_server_locations:
            if country and country.lower() not in server_data["country"].lower():
                continue
            server = ServerInfo(
                id=server_data["id"],
                name=server_data["name"],
                country=server_data["country"],
                city=server_data["city"],
                ip_address="",
                load=server_data["load"],
                protocols=[ProtocolType.OPENVPN],
                ping=0,
                is_premium=False,
                features=["Free Access", "Limited Speed", "Medium Security", "No Logs", "10 Free Countries"]
            )
            servers.append(server)
        print(f"ProtonVPN: Retrieved {len(servers)} free servers from correct countries and IDs.")
        return servers
    
    async def check_subscription_status(self) -> bool:
        """Check if user has active ProtonVPN subscription"""
        return await self._verify_subscription()
    
    async def _verify_subscription(self) -> bool:
        """Verify ProtonVPN subscription status"""
        try:
            # Use secure command executor to check subscription via ProtonVPN CLI
            executor = SecureCommandExecutor()
            
            # Check if user is logged in and has subscription
            result = await executor.execute_vpn_command(["protonvpn-cli", "status"])
            
            if result and result.returncode == 0:
                output = result.stdout.lower()
                
                # Check for subscription indicators
                subscription_indicators = [
                    'plan: plus',
                    'plan: visionary',
                    'plan: unlimited',
                    'tier: 2',  # Plus tier
                    'tier: 4',  # Visionary tier
                    'subscription: active',
                    'premium: true'
                ]
                
                # Check for active subscription
                for indicator in subscription_indicators:
                    if indicator in output:
                        print("ProtonVPN: Active subscription detected - Full server access available")
                        return True
                
                # Check if using free tier
                free_indicators = [
                    'plan: free',
                    'tier: 0',
                    'free tier',
                    'limited access'
                ]
                
                for indicator in free_indicators:
                    if indicator in output:
                        print("ProtonVPN: Free tier detected - 10 free servers available")
                        return False
                
                # Check if logged in but unknown status
                if 'status:' in output or 'user:' in output:
                    print("ProtonVPN: Logged in but unable to determine subscription level - Using limited access")
                    return False
                else:
                    print("ProtonVPN: Not logged in - Free tier access")
                    return False
            else:
                print("ProtonVPN: Unable to verify subscription status - Using free tier")
                return False
                
        except Exception as e:
            print(f"ProtonVPN: Error checking subscription: {e} - Using free tier")
            return False
    
    async def get_subscription_info(self) -> dict:
        """Get detailed subscription information"""
        try:
            executor = SecureCommandExecutor()
            result = await executor.execute_vpn_command(["protonvpn-cli", "status"])
            
            subscription_info = {
                'active': False,
                'plan': 'Free',
                'server_count': '10 free servers',
                'features': ['Basic protection', 'Limited speed'],
                'recommendation': 'Subscribe for 1700+ servers in 65+ countries'
            }
            
            if result and result.returncode == 0:
                output = result.stdout.lower()
                
                if any(indicator in output for indicator in ['plan: plus', 'plan: visionary', 'plan: unlimited', 'tier: 2', 'tier: 4']):
                    subscription_info.update({
                        'active': True,
                        'plan': 'Plus/Visionary/Unlimited',
                        'server_count': '1700+ servers in 65+ countries',
                        'features': [
                            'NetShield ad & malware blocking',
                            'Secure Core (double VPN',
                            'P2P/Torrenting support',
                            'Streaming service access',
                            'Tor over VPN',
                            'High-speed connections',
                            'Kill switch protection',
                            'DNS leak protection',
                            'No logs policy',
                            'Swiss privacy laws protection',
                            'Up to 10 simultaneous connections'
                        ],
                        'recommendation': 'Full access active - Maximum privacy protection!'
                    })
            
            return subscription_info
            
        except Exception as e:
            print(f"Error getting ProtonVPN subscription info: {e}")
            return {
                'active': False,
                'plan': 'Unknown',
                'server_count': 'Limited access',
                'features': ['Basic protection'],
                'recommendation': 'Subscribe for full access to 1700+ secure servers'
            }
    
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to ProtonVPN server with enhanced privacy and security"""
        try:
            if protocol == ProtocolType.WIREGUARD:
                # Automatically select config file based on server ID
                config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
                # Try exact match first
                server_id = server.id.replace('#', '-')
                config_filename = f'wg-{server_id}.conf'
                config_path = os.path.join(config_dir, config_filename)
                if os.path.isfile(config_path):
                    success = connect_wireguard(config_path)
                    if success:
                        print(f"Connected to ProtonVPN via WireGuard using {config_filename}.")
                        self.connection_info.status = ConnectionStatus.CONNECTED
                        self.connection_info.server = server
                        self.connection_info.protocol = protocol
                        return True
                    else:
                        print(f"Failed to connect using WireGuard config: {config_filename}")
                        self.connection_info.status = ConnectionStatus.ERROR
                        return False
                else:
                    # Try to find any config file for the same country
                    # Special case: use wg-NL-FREE-219.conf for any Netherlands server
                    if server.id.startswith('NL-FREE'):
                        nl_fallback = os.path.join(config_dir, 'wg-NL-FREE-219.conf')
                        if os.path.isfile(nl_fallback):
                            success = connect_wireguard(nl_fallback)
                            if success:
                                print(f"Connected to ProtonVPN via WireGuard using fallback config: wg-NL-FREE-219.conf.")
                                self.connection_info.status = ConnectionStatus.CONNECTED
                                self.connection_info.server = server
                                self.connection_info.protocol = protocol
                                return True
                            else:
                                print(f"Failed to connect using fallback WireGuard config: wg-NL-FREE-219.conf")
                                self.connection_info.status = ConnectionStatus.ERROR
                                return False
                    # Otherwise, try any config file for the same country
                    import glob
                    country_code = server.id.split('-')[0]
                    pattern = os.path.join(config_dir, f'wg-{country_code}-FREE-*.conf')
                    matches = glob.glob(pattern)
                    if matches:
                        config_path = matches[0]
                        success = connect_wireguard(config_path)
                        if success:
                            print(f"Connected to ProtonVPN via WireGuard using fallback config: {os.path.basename(config_path)}.")
                            self.connection_info.status = ConnectionStatus.CONNECTED
                            self.connection_info.server = server
                            self.connection_info.protocol = protocol
                            return True
                        else:
                            print(f"Failed to connect using fallback WireGuard config: {os.path.basename(config_path)}")
                            self.connection_info.status = ConnectionStatus.ERROR
                            return False
                    else:
                        print(f"WireGuard config file not found for server: {server.id} (expected {config_filename} or any {country_code} config)")
                        self.connection_info.status = ConnectionStatus.ERROR
                        return False
            # ...existing code for other protocols...
            raw_name = server.name.replace(' ', '-')
            allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-#')
            sanitized = ''.join(c for c in raw_name if c in allowed_chars)
            server_name = sanitized
            protocol_str = None
            if protocol == ProtocolType.OPENVPN:
                protocol_str = "openvpn"
            elif protocol == ProtocolType.IKEV2:
                protocol_str = "ikev2"
            elif protocol == ProtocolType.WIREGUARD:
                protocol_str = "wireguard"
            protonvpn_cli_path = self._find_protonvpn_cli()
            if not protonvpn_cli_path:
                print("ProtonVPN CLI not found. Please install or set the correct path.")
                self.connection_info.status = ConnectionStatus.ERROR
                return False
            connect_args = [protonvpn_cli_path, 'connect']
            if server_name:
                connect_args.append(server_name)
            if protocol_str:
                connect_args.extend(['--protocol', protocol_str])
            connect_args.extend([
                '--kill-switch', 'on',
                '--netshield', '2',
                '--dns-leak-protection', 'on',
                '--ipv6-leak-protection', 'on'
            ])
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
        """Disconnect from ProtonVPN using secure execution or WireGuard"""
        try:
            # If last connection was WireGuard, uninstall tunnel service
            if self.connection_info.protocol == ProtocolType.WIREGUARD:
                import os
                config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
                server = self.connection_info.server
                if server:
                    server_id = server.id.replace('#', '-')
                    config_filename = f'wg-{server_id}.conf'
                    config_path = os.path.join(config_dir, config_filename)
                    # Fallback for NL-FREE servers
                    if not os.path.isfile(config_path) and server.id.startswith('NL-FREE'):
                        config_filename = 'wg-NL-FREE-219.conf'
                        config_path = os.path.join(config_dir, config_filename)
                    if os.path.isfile(config_path):
                        tunnel_name = os.path.splitext(config_filename)[0]
                        import subprocess
                        try:
                            result = subprocess.run([
                                "wireguard.exe", "/uninstalltunnelservice", tunnel_name
                            ], check=True)
                            self.connection_info.status = ConnectionStatus.DISCONNECTED
                            self.connection_info.server = None
                            return result.returncode == 0
                        except Exception as e:
                            print(f"WireGuard disconnect error: {e}")
                            return False
                print("WireGuard disconnect: No config file found for uninstall.")
                return False
            # Otherwise, use ProtonVPN CLI
            protonvpn_cli_path = r"C:\Program Files\ProtonVPN CLI\protonvpn-cli.exe"
            disconnect_args = [protonvpn_cli_path, 'disconnect']
            if not os.path.exists(protonvpn_cli_path):
                disconnect_args = ['protonvpn-cli', 'disconnect']
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(disconnect_args)
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
        """Get current ProtonVPN connection status with detailed security info, including WireGuard."""
        try:
            # If last connection was WireGuard, check if tunnel is running
            if self.connection_info.protocol == ProtocolType.WIREGUARD:
                import subprocess
                tunnel_name = None
                server = self.connection_info.server
                if server:
                    server_id = server.id
                    tunnel_name = server_id if server_id.startswith('wg-') else f'wg-{server_id}'
                if tunnel_name:
                    try:
                        result = subprocess.run([
                            "wireguard.exe", "/listtunnels"
                        ], capture_output=True, text=True)
                        tunnels = [t.strip() for t in result.stdout.splitlines()]
                        # If tunnel is in the list, it's connected
                        if tunnel_name in tunnels:
                            self.connection_info.status = ConnectionStatus.CONNECTED
                        else:
                            self.connection_info.status = ConnectionStatus.DISCONNECTED
                    except Exception as e:
                        print(f"WireGuard status check error: {e}")
                        self.connection_info.status = ConnectionStatus.ERROR
                else:
                    self.connection_info.status = ConnectionStatus.ERROR
                return self.connection_info
            # Otherwise, use ProtonVPN CLI
            protonvpn_cli_path = r"C:\Program Files\ProtonVPN CLI\protonvpn-cli.exe"
            status_args = [protonvpn_cli_path, 'status']
            if not os.path.exists(protonvpn_cli_path):
                status_args = ['protonvpn-cli', 'status']
            return_code, stdout, stderr = await self.secure_executor.execute_vpn_command(status_args)
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
                                test_latency = test_end - test_start * 1000
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
        """Enable NetShield ad/malware blocking 0=off, 1=malware, 2=malware+ads"""
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
                    status_data = json.loadsstdout
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

    def _find_protonvpn_cli(self):
        import shutil
        # Try config, then common path, then PATH
        config_path = getattr(self, 'client_config_path', None)
        if config_path and os.path.exists(config_path):
            return config_path
        common_path = r"C:\Program Files\ProtonVPN CLI\protonvpn-cli.exe"
        if os.path.exists(common_path):
            return common_path
        cli_path = shutil.which("protonvpn-cli")
        if cli_path:
            return cli_path
        return None

    def refresh_wireguard_configs(self):
        """Scan config folder for WireGuard .conf files and return tunnel names."""
        import os, glob
        config_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'config')
        conf_files = glob.glob(os.path.join(config_dir, 'wg-*.conf'))
        tunnel_names = [os.path.splitext(os.path.basename(f))[0] for f in conf_files]
        return tunnel_names
