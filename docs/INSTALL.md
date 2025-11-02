# VPN Hub Installation and Setup Guide

## Prerequisites

Before installing VPN Hub, ensure you have the following:

### System Requirements
- **Windows 10/11**, **Linux (Ubuntu 18.04+, CentOS 7+)**, or **macOS 10.14+**
- **Python 3.8+** installed
- **Administrator/Root privileges** (recommended for full security features)
- **Internet connection** for downloading dependencies and VPN provider APIs

### Hardware Requirements
- **RAM**: Minimum 2GB, Recommended 4GB+
- **Storage**: 500MB free space
- **Network**: Ethernet or Wi-Fi connection

## Installation Steps

### 1. Download and Extract
```bash
# Clone the repository or download the ZIP file
git clone https://github.com/yourusername/vpn-hub.git
cd vpn-hub

# Or extract downloaded ZIP file
unzip vpn-hub.zip
cd vpn-hub
```

### 2. Install Python Dependencies
```bash
# Install required Python packages
pip install -r requirements.txt

# For development (optional)
pip install pytest pytest-asyncio  # For running tests
```

### 3. Install VPN Provider CLIs (Optional but Recommended)

For full functionality, install the official CLI tools for your VPN providers:

#### NordVPN
```bash
# Windows (via installer from nordvpn.com)
# Linux
sudo apt update
sudo apt install nordvpn

# macOS
brew install nordvpn
```

#### ExpressVPN
```bash
# Download from expressvpn.com and follow installation instructions
# Available for Windows, Linux, and macOS
```

#### Surfshark
```bash
# Download from surfshark.com and follow installation instructions
# Available for Windows, Linux, and macOS
```

### 4. Initial Setup

#### Run the Application
```bash
# Navigate to the src directory
cd src

# Start VPN Hub
python main.py
```

#### First-Time Configuration
1. **Launch VPN Hub** - The application will start with the GUI interface
2. **Add VPN Providers** - Go to the "Providers" tab and click "Add Provider"
3. **Enter Credentials** - Input your VPN provider username and password
4. **Configure Security** - Review security settings in the "Security" tab
5. **Test Connection** - Try connecting to a server to verify setup

## Configuration Guide

### Adding VPN Providers

1. **Open Providers Tab**
   - Click on the "Providers" tab in the main window
   - Click "Add Provider" button

2. **Select Provider Type**
   - Choose from: NordVPN, ExpressVPN, Surfshark, CyberGhost, ProtonVPN
   - Enter your account credentials

3. **Authentication**
   - The app will attempt to authenticate with the provider
   - Green status indicates successful authentication

### Security Settings

Navigate to the "Security" tab to configure:

#### Kill Switch
- **Enable Kill Switch**: Automatically blocks internet if VPN disconnects
- **Emergency Disconnect**: Manual trigger for immediate network lockdown

#### DNS Protection
- **Enable DNS Leak Protection**: Routes DNS queries through VPN
- **Custom DNS Servers**: Override with specific DNS servers

#### Auto-Reconnect
- **Enable Auto-Reconnect**: Automatically reconnects if connection drops
- **Retry Attempts**: Number of reconnection attempts

### Application Settings

Go to the "Settings" tab to configure:

#### General
- **Connect on Startup**: Automatically connect when app starts
- **Minimize to Tray**: Hide app in system tray when minimized
- **Update Interval**: Frequency of status updates (seconds)

#### Logging
- **Log Level**: INFO, DEBUG, WARNING, ERROR
- **Log Retention**: How long to keep log files

## Usage Instructions

### Basic Connection

1. **Select Provider**: Choose from configured providers in the "Connection" tab
2. **Choose Server**: Select a server location from the dropdown
3. **Select Protocol**: Choose connection protocol (Auto, OpenVPN, WireGuard, IKEv2)
4. **Connect**: Click "Connect" button

### Quick Connect
- Use the "Quick Connect" button for fastest available server
- Or use the system tray right-click menu

### Server Browser
- Use the "Servers" tab to browse all available servers
- Filter by country or provider
- View server load and features

### Connection History
- View past connections in the "History" tab
- Track connection duration and data usage
- Export history for analysis

## Advanced Features

### Command Line Interface
```bash
# Start with CLI mode (future feature)
python main.py --cli

# Show help
python main.py --help

# Show version
python main.py --version
```

### Configuration Export/Import
```python
# Through the application or programmatically
from core.config_manager import ConfigurationManager

config_manager = ConfigurationManager()

# Export configuration
config_manager.export_config("my_vpn_config.json", include_credentials=False)

# Import configuration
config_manager.import_config("my_vpn_config.json")
```

### Custom Provider Integration
```python
# Create custom provider by inheriting from VPNProviderInterface
from core.vpn_interface import VPNProviderInterface

class MyCustomVPN(VPNProviderInterface):
    def __init__(self, config):
        super().__init__("MyCustomVPN", config)
    
    async def authenticate(self, username, password):
        # Implement authentication logic
        pass
    
    # Implement other required methods...

# Register with factory
from providers import VPNProviderFactory
VPNProviderFactory.register_provider("mycustomvpn", MyCustomVPN)
```

## Troubleshooting

### Common Issues

#### Authentication Failed
- **Check Credentials**: Verify username/password are correct
- **Account Status**: Ensure VPN subscription is active
- **Network Connection**: Verify internet connectivity

#### Connection Fails
- **Firewall**: Check if firewall is blocking VPN traffic
- **Antivirus**: Some antivirus software blocks VPN connections
- **ISP Blocking**: Try different servers if ISP blocks VPN

#### Kill Switch Issues
- **Administrator Rights**: Kill switch requires elevated privileges
- **Firewall Rules**: May conflict with existing firewall configurations
- **Network Interfaces**: Check if network adapters are properly detected

#### GUI Not Starting
- **PyQt5 Installation**: Ensure PyQt5 is properly installed
- **Display Issues**: Try running with `--no-gui` flag (future feature)
- **Dependencies**: Check all requirements are installed

### Log Files

Logs are stored in the `logs/` directory:
- `vpn_hub.log`: Main application log
- `vpn_manager.log`: Connection manager log
- `security.log`: Security events log
- `config.log`: Configuration changes log

### Performance Optimization

#### For Better Performance:
- **Close Unused Apps**: Free up system resources
- **Wired Connection**: Use Ethernet for best performance
- **Server Selection**: Choose servers with low load
- **Protocol Choice**: WireGuard typically offers best performance

#### Memory Usage:
- **Monitor Usage**: Check Task Manager/Activity Monitor
- **Restart App**: Restart if memory usage grows too high
- **Log Cleanup**: Regularly clean old log files

### Network Configuration

#### Windows
```cmd
# Check network configuration
ipconfig /all

# Flush DNS
ipconfig /flushdns

# Reset network stack
netsh winsock reset
netsh int ip reset
```

#### Linux
```bash
# Check network configuration
ip addr show
ip route show

# Check DNS
cat /etc/resolv.conf

# Restart network manager
sudo systemctl restart NetworkManager
```

#### macOS
```bash
# Check network configuration
ifconfig
netstat -rn

# Flush DNS
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

## Security Considerations

### Data Protection
- **Encrypted Storage**: Credentials are encrypted using Fernet encryption
- **Keyring Integration**: Uses system keyring when available
- **File Permissions**: Configuration files have restricted permissions

### Network Security
- **Kill Switch**: Prevents data leaks during disconnections
- **DNS Protection**: Prevents DNS leak vulnerabilities
- **Leak Detection**: Monitors for IP, DNS, and WebRTC leaks

### Best Practices
- **Regular Updates**: Keep VPN Hub and provider apps updated
- **Strong Passwords**: Use strong, unique passwords for VPN accounts
- **Two-Factor Auth**: Enable 2FA on VPN provider accounts
- **Server Selection**: Choose servers in privacy-friendly jurisdictions

## Support and Updates

### Getting Help
- **Documentation**: Refer to README.md for basic information
- **Log Files**: Check log files for error details
- **Issue Tracker**: Report bugs on GitHub (if open source)
- **Community Forums**: Join user communities for tips

### Updates
- **Auto-Update**: Enable auto-update checking in settings
- **Manual Update**: Download latest version from official source
- **Changelog**: Review changelog before updating

### Contributing
- **Bug Reports**: Report issues with detailed information
- **Feature Requests**: Suggest new features
- **Code Contributions**: Submit pull requests
- **Documentation**: Help improve documentation

## Legal and Privacy

### Disclaimer
This application is for legitimate privacy and security purposes only. Users must:
- Comply with local laws and regulations
- Respect VPN provider terms of service
- Use responsibly and ethically

### Privacy Policy
- **No Data Collection**: VPN Hub does not collect user data
- **Local Storage**: All data stored locally on user device
- **Third-Party Services**: Subject to VPN provider privacy policies

### License
This project is licensed under the MIT License. See LICENSE file for details.