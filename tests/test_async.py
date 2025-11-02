#!/usr/bin/env python3
"""
Quick async functionality test
"""
import asyncio
import sys
sys.path.append('src')

from src.providers.nordvpn import NordVPNProvider
from src.providers.cyberghost import CyberGhostProvider
from src.providers.protonvpn import ProtonVPNProvider

async def test_providers():
    """Test async functionality of providers"""
    try:
        print("Testing async provider functionality...")
        
        # Test NordVPN
        nordvpn = NordVPNProvider({})
        protocols = await nordvpn.get_supported_protocols()
        print(f"✅ NordVPN protocols: {protocols}")
        
        # Test CyberGhost
        cyberghost = CyberGhostProvider({})
        protocols = await cyberghost.get_supported_protocols()
        print(f"✅ CyberGhost protocols: {protocols}")
        
        # Test ProtonVPN
        protonvpn = ProtonVPNProvider({})
        protocols = await protonvpn.get_supported_protocols()
        print(f"✅ ProtonVPN protocols: {protocols}")
        
        print("✅ All async provider tests passed!")
        
    except Exception as e:
        print(f"❌ Error in async test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_providers())