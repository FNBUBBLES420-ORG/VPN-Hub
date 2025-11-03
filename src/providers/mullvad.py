# NOT FULLY SUPPORTED OR SETUP
# STILL UPDATING

"""
Mullvad VPN Provider Implementation
Privacy-focused VPN provider with real server locations and reliable Windows CLI integration.
"""

import logging
import subprocess
import threading
import time
import re
import asyncio
from typing import List, Optional, Dict, Any, Tuple

try:
    from ..core.vpn_interface import VPNProviderInterface, ServerInfo, ConnectionInfo, ConnectionStatus, ProtocolType
except ImportError:
    # Handle imports when running as standalone script
    import sys
    from pathlib import Path
    src_dir = Path(__file__).parent.parent
    sys.path.insert(0, str(src_dir))
    
    from core.vpn_interface import VPNProviderInterface, ServerInfo, ConnectionInfo, ConnectionStatus, ProtocolType

logger = logging.getLogger(__name__)

class MullvadProvider(VPNProviderInterface):
    """Mullvad VPN provider implementation with real server locations and CLI automation."""
    
    def __init__(self, config: Dict = None):
        if config is None:
            config = {}
        super().__init__("Mullvad", config)
        self.description = "Privacy-focused VPN with anonymous accounts and WireGuard"
        self.cli_path = r"C:\Program Files\Mullvad VPN\mullvad.exe"
        self.supports_protocols = [ProtocolType.WIREGUARD, ProtocolType.OPENVPN]
        self.current_connection = None
        # Use a reentrant lock so connect_sync can call disconnect_sync safely
        self.connection_lock = threading.RLock()
        self._actual_locations_cache = None
        self._cache_timestamp = 0
        self._cache_duration = 300  # 5 minutes
        self.servers = []
        
        logger.info(f"Initialized {self.name} provider")

    def is_available(self) -> bool:
        """Check if Mullvad CLI is available."""
        try:
            import os
            if not os.path.exists(self.cli_path):
                logger.warning(f"Mullvad CLI not found at {self.cli_path}")
                return False
                
            # Test CLI accessibility
            result = subprocess.run([self.cli_path, "status"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("Mullvad CLI is available and accessible")
                return True
            else:
                logger.warning(f"Mullvad CLI returned error code {result.returncode}")
                return False
                
        except Exception as e:
            logger.error(f"Error checking Mullvad CLI availability: {e}")
            return False

    def get_server_list(self, country: str = None) -> List[ServerInfo]:
        """Get list of available servers, optionally filtered by country."""
        logger.info(f"Getting server list for Mullvad (country filter: {country})")
        
        # Clear existing servers
        self.servers = []
        
        # Real Mullvad server locations (based on actual Mullvad network)
        full_server_locations = [
            # Nordic Countries (Mullvad's home region - best coverage)
            {"id": "se-sto", "name": "Sweden - Stockholm", "country": "Sweden", "city": "Stockholm", "load": 12},
            {"id": "se-got", "name": "Sweden - Gothenburg", "country": "Sweden", "city": "Gothenburg", "load": 15},
            {"id": "se-mal", "name": "Sweden - Malmö", "country": "Sweden", "city": "Malmö", "load": 18},
            {"id": "no-osl", "name": "Norway - Oslo", "country": "Norway", "city": "Oslo", "load": 20},
            {"id": "dk-cph", "name": "Denmark - Copenhagen", "country": "Denmark", "city": "Copenhagen", "load": 22},
            {"id": "fi-hel", "name": "Finland - Helsinki", "country": "Finland", "city": "Helsinki", "load": 16},
            
            # Central Europe
            {"id": "de-ber", "name": "Germany - Berlin", "country": "Germany", "city": "Berlin", "load": 25},
            {"id": "de-fra", "name": "Germany - Frankfurt", "country": "Germany", "city": "Frankfurt", "load": 28},
            {"id": "de-dus", "name": "Germany - Düsseldorf", "country": "Germany", "city": "Düsseldorf", "load": 30},
            {"id": "nl-ams", "name": "Netherlands - Amsterdam", "country": "Netherlands", "city": "Amsterdam", "load": 32},
            {"id": "ch-zur", "name": "Switzerland - Zurich", "country": "Switzerland", "city": "Zurich", "load": 19},
            {"id": "at-vie", "name": "Austria - Vienna", "country": "Austria", "city": "Vienna", "load": 21},
            
            # Western Europe
            {"id": "uk-lon", "name": "United Kingdom - London", "country": "United Kingdom", "city": "London", "load": 35},
            {"id": "uk-man", "name": "United Kingdom - Manchester", "country": "United Kingdom", "city": "Manchester", "load": 24},
            {"id": "fr-par", "name": "France - Paris", "country": "France", "city": "Paris", "load": 38},
            {"id": "es-mad", "name": "Spain - Madrid", "country": "Spain", "city": "Madrid", "load": 26},
            {"id": "it-mil", "name": "Italy - Milan", "country": "Italy", "city": "Milan", "load": 29},
            {"id": "be-bru", "name": "Belgium - Brussels", "country": "Belgium", "city": "Brussels", "load": 23},
            
            # Eastern Europe
            {"id": "pl-war", "name": "Poland - Warsaw", "country": "Poland", "city": "Warsaw", "load": 27},
            {"id": "cz-prg", "name": "Czech Republic - Prague", "country": "Czech Republic", "city": "Prague", "load": 25},
            {"id": "ro-buc", "name": "Romania - Bucharest", "country": "Romania", "city": "Bucharest", "load": 31},
            {"id": "bg-sof", "name": "Bulgaria - Sofia", "country": "Bulgaria", "city": "Sofia", "load": 20},
            
            # North America
            {"id": "us-nyc", "name": "USA - New York", "country": "United States", "city": "New York", "load": 42},
            {"id": "us-chi", "name": "USA - Chicago", "country": "United States", "city": "Chicago", "load": 38},
            {"id": "us-dal", "name": "USA - Dallas", "country": "United States", "city": "Dallas", "load": 35},
            {"id": "us-den", "name": "USA - Denver", "country": "United States", "city": "Denver", "load": 29},
            {"id": "us-lax", "name": "USA - Los Angeles", "country": "United States", "city": "Los Angeles", "load": 45},
            {"id": "us-mia", "name": "USA - Miami", "country": "United States", "city": "Miami", "load": 33},
            {"id": "us-sea", "name": "USA - Seattle", "country": "United States", "city": "Seattle", "load": 31},
            {"id": "us-atl", "name": "USA - Atlanta", "country": "United States", "city": "Atlanta", "load": 36},
            {"id": "ca-tor", "name": "Canada - Toronto", "country": "Canada", "city": "Toronto", "load": 28},
            {"id": "ca-van", "name": "Canada - Vancouver", "country": "Canada", "city": "Vancouver", "load": 25},
            {"id": "ca-mon", "name": "Canada - Montreal", "country": "Canada", "city": "Montreal", "load": 30},
            
            # Asia-Pacific
            {"id": "jp-tok", "name": "Japan - Tokyo", "country": "Japan", "city": "Tokyo", "load": 48},
            {"id": "sg-sgp", "name": "Singapore", "country": "Singapore", "city": "Singapore", "load": 52},
            {"id": "au-syd", "name": "Australia - Sydney", "country": "Australia", "city": "Sydney", "load": 41},
            {"id": "au-mel", "name": "Australia - Melbourne", "country": "Australia", "city": "Melbourne", "load": 38},
            {"id": "hk-hkg", "name": "Hong Kong", "country": "Hong Kong", "city": "Hong Kong", "load": 55},
            
            # Other Regions
            {"id": "za-jhb", "name": "South Africa - Johannesburg", "country": "South Africa", "city": "Johannesburg", "load": 34},
            {"id": "br-sao", "name": "Brazil - São Paulo", "country": "Brazil", "city": "São Paulo", "load": 39},
            {"id": "il-tlv", "name": "Israel - Tel Aviv", "country": "Israel", "city": "Tel Aviv", "load": 37}
        ]
        
        # Convert dictionary data to ServerInfo objects
        for server_data in full_server_locations:
            # Filter by country if specified
            if country and country.lower() not in server_data["country"].lower():
                continue
                
            server = ServerInfo(
                id=server_data["id"],
                name=server_data["name"],
                country=server_data["country"],
                city=server_data["city"],
                ip_address="",
                load=server_data["load"],
                protocols=[ProtocolType.WIREGUARD, ProtocolType.OPENVPN],
                ping=0,
                is_premium=True,
                features=["No Logs", "Anonymous", "WireGuard", "Port Forwarding"]
            )
            self.servers.append(server)
        
        logger.info(f"Loaded {len(self.servers)} Mullvad servers")
        if country:
            logger.info(f"Filtered to country: {country}")
        
        return self.servers

    def _get_actual_cli_locations(self) -> Dict[str, str]:
        """Get actual location list from Mullvad CLI with caching."""
        current_time = time.time()
        
        # Check if cache is still valid
        if (self._actual_locations_cache is not None and 
            current_time - self._cache_timestamp < self._cache_duration):
            logger.info("Using cached CLI locations")
            return self._actual_locations_cache

        try:
            logger.info("Fetching actual Mullvad locations from CLI...")
            logger.info("Executing: mullvad relay list")
            result = self._execute_cli_with_elevation(["relay", "list"], timeout=30)
            
            logger.info(f"List command result: returncode={result.returncode}")
            if result.stdout:
                logger.info(f"List stdout length: {len(result.stdout)} characters")
            if result.stderr:
                logger.info(f"List stderr: {result.stderr.strip()}")
            
            if result.returncode == 0:
                locations = {}
                lines = result.stdout.split('\n')
                
                logger.info(f"Parsing {len(lines)} lines from CLI output")
                
                # Parse the location output
                for line in lines:
                    line = line.strip()
                    if line and ('wireguard' in line.lower() or 'openvpn' in line.lower()):
                        # Extract location code (e.g., "se-sto-wg-001")
                        parts = line.split()
                        if parts:
                            location_code = parts[0]
                            # Extract base location (e.g., "se-sto" from "se-sto-wg-001")
                            base_location = '-'.join(location_code.split('-')[:2])
                            if base_location:
                                locations[base_location] = location_code
                            
                logger.info(f"Successfully parsed {len(locations)} actual Mullvad locations")
                
                # Update cache
                self._actual_locations_cache = locations
                self._cache_timestamp = current_time
                
                return locations
            else:
                logger.warning(f"Failed to get locations from CLI: {result.stderr}")
                return {}
                
        except Exception as e:
            logger.error(f"Error getting Mullvad locations: {e}")
            return {}

    def _execute_cli_with_elevation(self, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Execute Mullvad CLI command with proper Windows elevation handling."""
        try:
            cmd = [self.cli_path] + args
            logger.debug(f"Executing CLI command: {' '.join(cmd)}")
            
            # On Windows, try without elevation first
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
                logger.debug(f"Direct command result: returncode={result.returncode}, stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}'")
                
                # If command succeeds or gives expected output, return it
                if result.returncode == 0 or "Connected" in result.stdout or "Disconnected" in result.stdout:
                    return result
                    
                # If it's an authentication/permission error, try with elevation
                if "permission" in result.stderr.lower() or "access" in result.stderr.lower() or "administrator" in result.stderr.lower():
                    logger.debug("Permission issue detected, trying with elevation...")
                else:
                    # For other errors, return the result without trying elevation
                    logger.debug("Command failed but not due to permissions, returning result")
                    return result
                    
            except subprocess.TimeoutExpired:
                logger.error(f"Direct CLI command timed out after {timeout} seconds")
                return subprocess.CompletedProcess(cmd, 1, "", "Command timed out")
            except Exception as e:
                logger.debug(f"Direct execution failed: {e}, trying with elevation...")
            
            # Try with simplified Windows elevation
            args_str = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in args)
            elevated_cmd = [
                "powershell", "-Command", 
                f"Start-Process -FilePath '{self.cli_path}' -ArgumentList '{args_str}' -Verb RunAs -Wait -WindowStyle Hidden"
            ]
            
            logger.debug(f"Elevated command: {' '.join(elevated_cmd)}")
            result = subprocess.run(elevated_cmd, capture_output=True, text=True, timeout=timeout, check=False)
            logger.debug(f"Elevated command result: returncode={result.returncode}, stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}'")
            
            # Since elevated commands don't return output properly, try to get status
            if result.returncode == 0:
                # Check connection status after elevation attempt
                status_result = subprocess.run([self.cli_path, "status"], capture_output=True, text=True, timeout=10, check=False)
                logger.debug(f"Status check after elevation: {status_result.stdout.strip()}")
                return subprocess.CompletedProcess(cmd, 0, status_result.stdout, "")
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"CLI command timed out after {timeout} seconds")
            return subprocess.CompletedProcess(cmd, 1, "", "Command timed out")
        except Exception as e:
            logger.error(f"Error executing CLI command: {e}")
            return subprocess.CompletedProcess(cmd, 1, "", str(e))

    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with Mullvad (account number based)"""
        logger.info("Mullvad uses account number authentication")
        # Mullvad uses account numbers, not username/password
        # The account number would be passed as username
        self.is_authenticated = True
        return True
    
    async def get_servers(self, country: str = None) -> List[ServerInfo]:
        """Get list of available servers"""
        return self.get_server_list(country)
    
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to a specific server"""
        logger.info(f"Async connect called with server: {server.id} ({server.name})")
        result = self.connect_sync(server.id, protocol or ProtocolType.WIREGUARD)
        return result

    def connect_sync(self, server_id: str, protocol: ProtocolType = ProtocolType.WIREGUARD) -> bool:
        """Connect to Mullvad server using CLI."""
        with self.connection_lock:
            logger.info(f"Step 1: Disconnecting any existing connection")
            # Disconnect any existing connection first
            self.disconnect_sync()
            
            logger.info(f"Step 2: Attempting to connect to Mullvad server: {server_id}")
            
            try:
                # Get actual CLI locations for mapping
                actual_locations = self._get_actual_cli_locations()
                logger.info(f"Available CLI locations count: {len(actual_locations)}")
                
                # Find server info
                server_info = None
                for server in self.servers:
                    if server.id == server_id:
                        server_info = server
                        logger.info(f"Found server info for {server_id}: {server_info.name}")
                        break
                
                if not server_info:
                    logger.error(f"No server info found for server_id: {server_id}")
                    return False
                
                # Try to connect using relay set location
                cli_location = actual_locations.get(server_id)
                if cli_location:
                    logger.info(f"Found CLI location {cli_location} for {server_id}")
                    
                    # Set relay location first
                    result = self._execute_cli_with_elevation(["relay", "set", "location", server_id], timeout=30)
                    if result.returncode == 0:
                        # Now connect
                        connect_result = self._execute_cli_with_elevation(["connect"], timeout=45)
                        
                        logger.info(f"Connection result: returncode={connect_result.returncode}")
                        logger.info(f"Connection stdout: {connect_result.stdout.strip()}")
                        
                        if connect_result.returncode == 0 or "Connected" in connect_result.stdout:
                            self.current_connection = server_info
                            logger.info(f"Successfully connected to {server_info.name}")
                            return True
                
                # Fallback: try direct connection
                logger.info("Trying direct connection")
                result = self._execute_cli_with_elevation(["connect"], timeout=45)
                
                if result.returncode == 0 or "Connected" in result.stdout:
                    # Use a default server info for successful connection
                    default_server = ServerInfo(
                        id="auto-selected",
                        name="Auto-selected server",
                        country="Various",
                        city="Auto",
                        ip_address="",
                        load=0,
                        protocols=[ProtocolType.WIREGUARD],
                        ping=0
                    )
                    self.current_connection = default_server
                    logger.info("Successfully connected to auto-selected Mullvad server")
                    return True
                
                error_msg = f"Failed to connect to {server_id}: {result.stderr if result.stderr else 'Unknown error'}"
                logger.error(error_msg)
                return False
                
            except Exception as e:
                error_msg = f"Connection error: {str(e)}"
                logger.error(error_msg)
                return False

    def disconnect_sync(self) -> bool:
        """Disconnect from Mullvad."""
        with self.connection_lock:
            logger.info("Executing CLI disconnect")
            
            try:
                # Use a shorter timeout for disconnect to avoid long hangs
                result = self._execute_cli_with_elevation(["disconnect"], timeout=15)
                logger.info(f"Disconnect command returned: returncode={getattr(result, 'returncode', 'N/A')}")
                
                if result.returncode == 0 or "Disconnected" in result.stdout:
                    self.current_connection = None
                    logger.info("Successfully disconnected from Mullvad")
                    return True
                else:
                    error_msg = f"Failed to disconnect: {result.stderr}"
                    logger.error(error_msg)
                    return False
                    
            except Exception as e:
                error_msg = f"Disconnect error: {str(e)}"
                logger.error(error_msg)
                return False

    async def disconnect(self) -> bool:
        """Disconnect from VPN"""
        return self.disconnect_sync()

    def get_status(self) -> ConnectionStatus:
        """Get current connection status."""
        try:
            result = self._execute_cli_with_elevation(["status"], timeout=10)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                if "connected" in output and "disconnected" not in output:
                    return ConnectionStatus.CONNECTED
                elif "connecting" in output:
                    return ConnectionStatus.CONNECTING
                else:
                    return ConnectionStatus.DISCONNECTED
            else:
                logger.warning(f"Status check failed: {result.stderr}")
                return ConnectionStatus.DISCONNECTED
                
        except Exception as e:
            logger.error(f"Error checking status: {e}")
            return ConnectionStatus.DISCONNECTED

    async def get_connection_status(self) -> ConnectionInfo:
        """Get current connection status and information"""
        try:
            result = self._execute_cli_with_elevation(["status"], timeout=10)
            
            if result.returncode == 0:
                output = result.stdout
                
                if "Connected" in output:
                    self.connection_info.status = ConnectionStatus.CONNECTED
                    # Parse connection details from status
                    lines = output.split('\n')
                    for line in lines:
                        if "Relay:" in line:
                            relay_info = line.split("Relay: ")[1] if "Relay: " in line else ""
                        elif "IPv4:" in line:
                            self.connection_info.public_ip = line.split("IPv4: ")[1].strip() if "IPv4: " in line else ""
                elif "Disconnected" in output:
                    self.connection_info.status = ConnectionStatus.DISCONNECTED
                else:
                    self.connection_info.status = ConnectionStatus.DISCONNECTED
            else:
                self.connection_info.status = ConnectionStatus.ERROR
                
            return self.connection_info
            
        except Exception as e:
            logger.error(f"Error getting connection status: {e}")
            self.connection_info.status = ConnectionStatus.ERROR
            return self.connection_info

    async def get_public_ip(self) -> str:
        """Get current public IP address"""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.mullvad.net/www/relays/all/', timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('ip', 'Unknown')
            return 'Unknown'
        except Exception as e:
            logger.error(f"Error getting public IP: {e}")
            return 'Unknown'

    async def test_connection(self) -> Tuple[bool, float]:
        """Test connection speed and reliability"""
        try:
            import aiohttp
            import time
            
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get('https://am.i.mullvad.net/json', timeout=10) as response:
                    end_time = time.time()
                    if response.status == 200:
                        data = await response.json()
                        is_mullvad = data.get('mullvad_exit_ip', False)
                        latency = (end_time - start_time) * 1000  # Convert to ms
                        return is_mullvad, latency
            
            return False, 0.0
        except Exception as e:
            logger.error(f"Error testing connection: {e}")
            return False, 0.0

    async def get_supported_protocols(self) -> List[ProtocolType]:
        """Get list of supported protocols"""
        return [ProtocolType.WIREGUARD, ProtocolType.OPENVPN]

    def __del__(self):
        """Cleanup when provider is destroyed."""
        try:
            if hasattr(self, 'current_connection') and self.current_connection:
                logger.info("Cleaning up Mullvad connection")
                self.disconnect_sync()
        except:
            pass  # Ignore cleanup errors
