"""
Base VPN Provider Interface
Defines the contract that all VPN providers must implement
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import asyncio

class ConnectionStatus(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"

class ProtocolType(Enum):
    OPENVPN = "openvpn"
    WIREGUARD = "wireguard"
    IKEV2 = "ikev2"
    L2TP = "l2tp"
    PPTP = "pptp"
    SSTP = "sstp"

@dataclass
class ServerInfo:
    """Information about a VPN server"""
    id: str
    name: str
    country: str
    city: str
    ip_address: str
    load: float  # 0-100 percentage
    ping: Optional[int] = None
    protocols: List[ProtocolType] = None
    is_premium: bool = False
    features: List[str] = None  # e.g., ["P2P", "Streaming", "Double VPN"]

@dataclass
class ConnectionInfo:
    """Information about current connection"""
    status: ConnectionStatus
    server: Optional[ServerInfo] = None
    protocol: Optional[ProtocolType] = None
    public_ip: Optional[str] = None
    dns_servers: List[str] = None
    connected_since: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0

class VPNProviderInterface(ABC):
    """Abstract base class for all VPN providers"""
    
    def __init__(self, name: str, config: Dict):
        self.name = name
        self.config = config
        self.is_authenticated = False
        self.connection_info = ConnectionInfo(status=ConnectionStatus.DISCONNECTED)
    
    @abstractmethod
    async def authenticate(self, username: str, password: str) -> bool:
        """Authenticate with the VPN provider"""
        pass
    
    @abstractmethod
    async def get_servers(self, country: str = None) -> List[ServerInfo]:
        """Get list of available servers"""
        pass
    
    @abstractmethod
    async def connect(self, server: ServerInfo, protocol: ProtocolType = None) -> bool:
        """Connect to a specific server"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> bool:
        """Disconnect from current server"""
        pass
    
    @abstractmethod
    async def get_connection_status(self) -> ConnectionInfo:
        """Get current connection status and information"""
        pass
    
    @abstractmethod
    async def get_public_ip(self) -> str:
        """Get current public IP address"""
        pass
    
    @abstractmethod
    async def test_connection(self) -> Tuple[bool, float]:
        """Test connection speed and reliability"""
        pass
    
    @abstractmethod
    async def get_supported_protocols(self) -> List[ProtocolType]:
        """Get list of supported protocols"""
        pass
    
    def __str__(self):
        return f"VPN Provider: {self.name}"
    
    def __repr__(self):
        return f"VPNProvider(name='{self.name}', authenticated={self.is_authenticated})"
