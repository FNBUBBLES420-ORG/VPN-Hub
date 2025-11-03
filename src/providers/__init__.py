"""
VPN Provider Factory
Manages creation and registration of VPN providers
"""

from typing import Dict, List, Type, Optional
try:
    from ..core.vpn_interface import VPNProviderInterface
    from .nordvpn import NordVPNProvider
    from .expressvpn import ExpressVPNProvider
    from .surfshark import SurfsharkProvider
    from .cyberghost import CyberGhostProvider
    from .protonvpn import ProtonVPNProvider
    from .mullvad import MullvadProvider
except ImportError:
    # Handle imports when running as standalone script
    import sys
    from pathlib import Path
    src_dir = Path(__file__).parent.parent
    sys.path.insert(0, str(src_dir))
    
    from core.vpn_interface import VPNProviderInterface
    from providers.nordvpn import NordVPNProvider
    from providers.expressvpn import ExpressVPNProvider
    from providers.surfshark import SurfsharkProvider
    from providers.cyberghost import CyberGhostProvider
    from providers.protonvpn import ProtonVPNProvider
    from providers.mullvad import MullvadProvider

class VPNProviderFactory:
    """Factory class for creating VPN provider instances"""
    
    _providers: Dict[str, Type[VPNProviderInterface]] = {
        "nordvpn": NordVPNProvider,
        "expressvpn": ExpressVPNProvider,
        "surfshark": SurfsharkProvider,
        "cyberghost": CyberGhostProvider,
        "protonvpn": ProtonVPNProvider,
        "mullvad": MullvadProvider,
    }
    
    @classmethod
    def register_provider(cls, name: str, provider_class: Type[VPNProviderInterface]):
        """Register a new VPN provider"""
        cls._providers[name.lower()] = provider_class
    
    @classmethod
    def create_provider(cls, name: str, config: Dict) -> Optional[VPNProviderInterface]:
        """Create a VPN provider instance"""
        provider_class = cls._providers.get(name.lower())
        if provider_class:
            return provider_class(config)
        return None
    
    @classmethod
    def get_available_providers(cls) -> List[str]:
        """Get list of available provider names"""
        return list(cls._providers.keys())
    
    @classmethod
    def is_provider_available(cls, name: str) -> bool:
        """Check if a provider is available"""
        return name.lower() in cls._providers

    @classmethod
    def is_provider_available(cls, name: str) -> bool:
        """Check if a provider is available"""
        return name.lower() in cls._providers
