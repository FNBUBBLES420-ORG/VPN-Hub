# VPN Hub Icons

This directory contains all icon assets used throughout the VPN Hub application.

## Icon Categories

### App Icons (`app/`)
- **vpn-hub-icon-16.png**: 16x16 system tray icon
- **vpn-hub-icon-32.png**: 32x32 window icon
- **vpn-hub-icon-64.png**: 64x64 application icon
- **vpn-hub-icon-128.png**: 128x128 high-res application icon
- **vpn-hub-icon-256.png**: 256x256 dock/taskbar icon
- **vpn-hub-icon.ico**: Windows ICO format (multi-size)
- **vpn-hub-icon.icns**: macOS ICNS format
- **vpn-hub-logo.svg**: Scalable vector logo

### Provider Icons (`providers/`)
- **nordvpn-logo.png**: NordVPN provider logo
- **expressvpn-logo.png**: ExpressVPN provider logo
- **surfshark-logo.png**: Surfshark provider logo
- **cyberghost-logo.png**: CyberGhost provider logo
- **pia-logo.png**: Private Internet Access logo
- **protonvpn-logo.png**: ProtonVPN provider logo
- **default-provider.png**: Generic provider icon

### Status Icons (`status/`)
- **connected.png**: Green checkmark for connected state
- **disconnected.png**: Red X for disconnected state
- **connecting.png**: Yellow loading for connecting state
- **error.png**: Red warning for error state
- **secure.png**: Shield icon for secure connection
- **warning.png**: Orange triangle for warnings
- **blocked.png**: Stop sign for blocked connections

### UI Icons (`ui/`)
- **settings.png**: Gear icon for settings
- **refresh.png**: Circular arrow for refresh
- **power.png**: Power button for connect/disconnect
- **list.png**: List view icon
- **grid.png**: Grid view icon
- **search.png**: Magnifying glass for search
- **filter.png**: Funnel icon for filtering
- **sort.png**: Up/down arrows for sorting
- **back.png**: Left arrow for navigation
- **forward.png**: Right arrow for navigation
- **home.png**: House icon for home/dashboard
- **stats.png**: Bar chart for statistics
- **logs.png**: Document icon for logs
- **security.png**: Lock icon for security features
- **network.png**: Globe icon for network features

## Icon Specifications

### Formats
- **PNG**: For most UI elements (24-bit with alpha)
- **SVG**: For scalable graphics and logos
- **ICO**: For Windows application icons
- **ICNS**: For macOS application icons

### Sizes
- **16x16**: System tray, small UI elements
- **24x24**: Standard UI buttons and icons
- **32x32**: Medium UI elements, window icons
- **48x48**: Large UI elements, dialog icons
- **64x64**: Application icons, provider logos
- **128x128**: High-DPI application icons
- **256x256**: Extra high-DPI, dock icons

### Design Guidelines
- Use consistent color scheme matching app theme
- Maintain 2px padding for clickable icons
- Ensure high contrast for accessibility
- Optimize file sizes for quick loading
- Support both light and dark themes where applicable

## Usage in Code

```python
# Loading icons in the application
from pathlib import Path

ASSETS_DIR = Path(__file__).parent.parent / "assets"
ICONS_DIR = ASSETS_DIR / "icons"

# Load status icons
CONNECTED_ICON = ICONS_DIR / "status" / "connected.png"
DISCONNECTED_ICON = ICONS_DIR / "status" / "disconnected.png"

# Load provider icons
NORDVPN_ICON = ICONS_DIR / "providers" / "nordvpn-logo.png"
EXPRESSVPN_ICON = ICONS_DIR / "providers" / "expressvpn-logo.png"
```

## Security Considerations

All icon files should be:
- ✅ Scanned for embedded malware
- ✅ Validated for proper image format
- ✅ Optimized for size and performance
- ✅ Digitally signed for integrity
- ✅ Licensed appropriately for use