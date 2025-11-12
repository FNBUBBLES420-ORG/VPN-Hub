# VPN Hub User Manual

Complete user guide for VPN Hub enterprise-grade secure VPN manager.

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [User Interface Guide](#user-interface-guide)
- [Provider Setup](#provider-setup)
- [Connection Management](#connection-management)
- [Security Features](#security-features)
- [Settings and Preferences](#settings-and-preferences)
- [Troubleshooting](#troubleshooting)

## 🚀 Getting Started

### **First Time Setup**

1. **Download and Install**
   - Download VPN Hub from the official repository
   - Extract to your preferred directory
   - Install Python dependencies: `pip install -r requirements.txt`

2. **Initial Launch**
   - Run: `python src/main.py`
   - The application will open with the main interface
   - A setup wizard will guide you through initial configuration

3. **Add Your First VPN Provider**
   - Click "Add Provider" in the main window
   - Select your VPN service (NordVPN, ExpressVPN, etc.)
   - Enter your credentials securely
   - Test the connection

### **System Requirements**
- **Operating System**: Windows 10+, macOS 10.15+, Linux (Ubuntu 20.04+)
- **Python**: 3.8 or higher (3.11+ recommended)
- **Memory**: 4GB RAM minimum, 8GB recommended
- **Storage**: 500MB free space
- **Privileges**: Administrator/root access for full functionality

## 🖥️ User Interface Guide

### **Main Window Layout**

```
┌─────────────────────────────────────────────────────────┐
│ File  Connect  Tools  Security  Help               [_][□][X] │
├─────────────────────────────────────────────────────────┤
│ 🔒 VPN Hub - Enterprise Security                        │
├─────────────────────────────────────────────────────────┤
│ Provider: [NordVPN         ▼]  Status: ● Connected      │
│ Server:   [Auto-Select     ▼]  IP: 203.0.113.1        │
│                                                         │
│ ┌─────────────────┐ ┌─────────────────┐ ┌──────────────┐ │
│ │   🔌 Connect    │ │  🔌 Disconnect  │ │ ⚙️ Settings  │ │
│ └─────────────────┘ └─────────────────┘ └──────────────┘ │
│                                                         │
│ Security Status: 🛡️ PROTECTED                          │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 🔒 Kill Switch: ON     📡 DNS Protection: ON       │ │
│ │ 🚫 Ad Blocking: ON     🔍 Leak Detection: OK       │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ Recent Connections:                                     │
│ ├─ NordVPN - New York (us3045) - 2 hours ago          │
│ ├─ ExpressVPN - London (uk-1) - Yesterday             │
│ └─ Surfshark - Germany (de-ber) - 2 days ago          │
└─────────────────────────────────────────────────────────┘
```

### **Menu Bar Options**

#### **File Menu**
- **New Connection**: Quick connect to any provider
- **Import Settings**: Import configuration from file
- **Export Settings**: Save current configuration
- **Exit**: Close application (with confirmation)

#### **Connect Menu**
- **Quick Connect**: Auto-select optimal server
- **Connect to Specific Server**: Choose exact server
- **Disconnect**: End current VPN session
- **Reconnect**: Restart current connection

#### **Tools Menu**
- **Speed Test**: Test connection performance
- **IP Leak Test**: Check for IP/DNS leaks
- **Connection Log**: View detailed connection history
- **System Information**: Display network status

#### **Security Menu**
- **Security Dashboard**: Real-time security monitoring
- **Scan for Threats**: Run security assessment
- **Update Security Rules**: Refresh security definitions
- **Security Reports**: View detailed security analytics

#### **Help Menu**
- **User Manual**: Open this documentation
- **Quick Start Guide**: 5-minute setup tutorial
- **Check for Updates**: Update application
- **About**: Version and license information

### **System Tray Integration**

VPN Hub runs in the system tray for convenient access:

**Right-click tray icon for quick menu:**
```
🔒 VPN Hub
├─ 🔌 Quick Connect
├─ 🔌 Disconnect
├─ 📊 Status Dashboard
├─ ⚙️ Settings
├─ 📖 Help
└─ ❌ Exit
```

**Tray Icon Status Indicators:**
- 🔒 **Green**: Connected and secure
- 🟡 **Yellow**: Connecting or reconnecting
- 🔴 **Red**: Disconnected or error
- ⚫ **Gray**: Application starting or disabled

## 🔌 Provider Setup

### **Adding NordVPN**

1. **Account Preparation**
   - Ensure you have an active NordVPN subscription
   - Note your login credentials
   - Enable 2FA if available (recommended)

2. **Setup Process**
   ```
   1. Click "Add Provider" or File → New Connection
   2. Select "NordVPN" from provider list
   3. Enter credentials:
      - Username: your@email.com
      - Password: your_secure_password
   4. Click "Test Connection"
   5. If successful, click "Save"
   ```

3. **Advanced NordVPN Options**
   - **CyberSec**: Enable malware and ad blocking
   - **Auto-Connect**: Automatically connect on startup
   - **Kill Switch**: Block internet if VPN disconnects
   - **Custom DNS**: Use NordVPN's secure DNS servers

### **Adding ExpressVPN**

1. **Activation Code Required**
   - Log into your ExpressVPN account
   - Navigate to "Set up on more devices"
   - Copy your activation code

2. **Setup Process**
   ```
   1. Select "ExpressVPN" from provider list
   2. Enter activation code (not username/password)
   3. Click "Activate"
   4. Choose preferred protocol (Lightway recommended)
   5. Test connection and save
   ```

3. **ExpressVPN Features**
   - **Lightway Protocol**: Fastest connection option
   - **Smart Location**: Auto-select optimal server
   - **Split Tunneling**: Route specific apps outside VPN
   - **Network Lock**: ExpressVPN's kill switch

### **Adding Surfshark**

1. **Credentials Setup**
   - Use your Surfshark email and password
   - Enable 2FA in your Surfshark account

2. **Setup Process**
   ```
   1. Select "Surfshark" from provider list
   2. Enter email and password
   3. Configure features:
      - CleanWeb (ad blocking)
      - Whitelister (split tunneling)
      - Kill Switch
   4. Test and save configuration
   ```

### **Adding CyberGhost**

1. **Account Information**
   - Username and password from CyberGhost account
   - Note your subscription plan for server access

2. **Setup Process**
   ```
   1. Select "CyberGhost" from provider list
   2. Enter username and password
   3. Choose server specialization:
      - Streaming (optimized for video services)
      - Torrenting (P2P optimized)
      - Gaming (low latency)
   4. Test connection and save
   ```

### **Adding ProtonVPN**

1. **OpenVPN Credentials**
   - Different from web login credentials
   - Generate OpenVPN credentials in ProtonVPN dashboard

2. **Setup Process**
   ```
   1. Select "ProtonVPN" from provider list
   2. Enter OpenVPN username and password
   3. Configure advanced features:
      - Secure Core (maximum security)
      - NetShield (ad/tracker blocking)
      - Tor over VPN
   4. Test connection and save
   ```

## 🔗 Connection Management

### **Connecting to VPN**

#### **Quick Connect**
1. **One-Click Connection**
   - Click the large "Connect" button
   - VPN Hub will auto-select optimal server
   - Connection typically takes 10-30 seconds

2. **Auto-Selection Criteria**
   - Server load (prefers lower load)
   - Geographic proximity
   - Connection speed
   - Available features

#### **Manual Server Selection**
1. **Choose Specific Server**
   ```
   1. Click server dropdown menu
   2. Browse servers by country/city
   3. Check server information:
      - Load percentage
      - Distance from you
      - Available features
      - Connection speed
   4. Select desired server
   5. Click "Connect"
   ```

2. **Server Information Display**
   ```
   🇺🇸 United States - New York
   ├─ us3045.nordvpn.com
   ├─ Load: 15% (Excellent)
   ├─ Distance: 342 km
   ├─ Features: P2P, Streaming
   └─ Protocols: OpenVPN, WireGuard
   ```

### **Connection Status Monitoring**

#### **Real-time Status Display**
```
Connection Status: 🟢 CONNECTED
├─ Provider: NordVPN
├─ Server: us3045.nordvpn.com
├─ Location: New York, United States
├─ IP Address: 203.0.113.45
├─ Protocol: WireGuard
├─ Encryption: ChaCha20-Poly1305
├─ Connected Since: 14:32:15
└─ Data Transferred: ↓ 125 MB ↑ 23 MB
```

#### **Connection Quality Indicators**
- **🟢 Excellent**: Low latency, high speed
- **🟡 Good**: Moderate performance
- **🟠 Fair**: Acceptable for basic usage
- **🔴 Poor**: Connection issues detected

### **Disconnecting from VPN**

#### **Normal Disconnection**
1. Click "Disconnect" button
2. Wait for confirmation (usually 2-5 seconds)
3. Status changes to "Disconnected"
4. Original IP address restored

#### **Emergency Disconnection**
- **Hotkey**: Ctrl+Shift+D (Windows/Linux) or Cmd+Shift+D (macOS)
- **System Tray**: Right-click → Emergency Disconnect
- **Kill Switch**: Automatically triggered on connection loss

## 🛡️ Security Features

### **Kill Switch Protection**

#### **How It Works**
The kill switch monitors your VPN connection and blocks internet access if the VPN disconnects unexpectedly.

#### **Enable Kill Switch**
```
1. Go to Settings → Security
2. Check "Enable Kill Switch"
3. Choose protection level:
   - Standard: Block all internet
   - Allow LAN: Block internet but allow local network
   - Custom: Configure specific rules
4. Click "Apply"
```

#### **Kill Switch Indicator**
```
🛡️ Kill Switch Status: ACTIVE
├─ Protection Level: Standard
├─ Blocked Connections: 0
├─ Last Triggered: Never
└─ Status: Monitoring
```

### **DNS Leak Protection**

#### **Automatic DNS Protection**
- Automatically routes DNS queries through VPN
- Prevents your ISP from seeing websites you visit
- Uses secure DNS servers (1.1.1.1, 8.8.8.8, 9.9.9.9)

#### **DNS Leak Testing**
```
1. Go to Tools → IP Leak Test
2. Click "Run DNS Leak Test"
3. Review results:
   ✅ No leaks detected
   ❌ DNS leak found (ISP DNS visible)
```

### **Advanced Security Features**

#### **Real-time Threat Monitoring**
```
🔍 Security Monitor: ACTIVE
├─ Threats Blocked: 0
├─ Malicious Sites: 0
├─ Trackers Blocked: 247
└─ Last Scan: 2 minutes ago
```

#### **Connection Encryption**
- **OpenVPN**: AES-256-CBC encryption
- **WireGuard**: ChaCha20-Poly1305 encryption
- **IKEv2**: AES-256-GCM encryption
- **Certificate Pinning**: Prevents man-in-the-middle attacks

### **Privacy Protection**

#### **No-Logs Policy Verification**
All supported providers maintain strict no-logs policies:
- **NordVPN**: Independently audited no-logs
- **ExpressVPN**: Third-party verified
- **Surfshark**: RAM-only servers
- **CyberGhost**: Annual transparency reports
- **ProtonVPN**: Open-source, Swiss privacy laws

#### **IP Address Protection**
```
🌐 IP Protection Status
├─ Original IP: Hidden
├─ VPN IP: 203.0.113.45
├─ Location: New York, US
├─ ISP: NordVPN
└─ IPv6: Disabled (secure)
```

## ⚙️ Settings and Preferences

### **General Settings**

#### **Application Behavior**
```
Application Settings
├─ 🚀 Start with Windows: ☑️ Enabled
├─ 🔄 Auto-connect on startup: ☑️ Enabled
├─ 📱 Minimize to system tray: ☑️ Enabled
├─ 🔔 Show notifications: ☑️ Enabled
└─ 🌐 Check for updates: ☑️ Weekly
```

#### **User Interface Options**
```
Interface Settings
├─ 🎨 Theme: Dark (Light/Dark/Auto)
├─ 🗣️ Language: English
├─ 📏 Window size: Remember last size
├─ 📍 Window position: Center screen
└─ 🔤 Font size: Medium
```

### **Security Settings**

#### **Connection Security**
```
Security Configuration
├─ 🛡️ Kill Switch: ☑️ Enabled
├─ 🔒 DNS Leak Protection: ☑️ Enabled
├─ 📡 IPv6 Blocking: ☑️ Enabled
├─ 🚫 Block malware: ☑️ Enabled
└─ 🔍 Real-time scanning: ☑️ Enabled
```

#### **Advanced Security**
```
Advanced Security
├─ 🔐 Certificate Pinning: ☑️ Enabled
├─ 🛠️ Debug Logging: ☐ Disabled
├─ 📊 Anonymous Usage Stats: ☐ Disabled
├─ 🔄 Auto-reconnect attempts: 3
└─ ⏱️ Connection timeout: 30 seconds
```

### **Network Settings**

#### **Protocol Preferences**
```
Protocol Settings
├─ 🥇 Preferred: WireGuard
├─ 🥈 Fallback: OpenVPN
├─ 🥉 Backup: IKEv2
├─ 🚫 Disabled: PPTP, L2TP
└─ 🔄 Auto-select optimal: ☑️ Enabled
```

#### **Custom DNS Configuration**
```
DNS Settings
├─ 🔄 Use VPN provider DNS: ☑️ Enabled
├─ 🔒 Custom DNS servers:
│   ├─ Primary: 1.1.1.1 (Cloudflare)
│   └─ Secondary: 8.8.8.8 (Google)
├─ 🌐 DNS over HTTPS: ☑️ Enabled
└─ 🔐 DNS over TLS: ☑️ Enabled
```

### **Notification Settings**

#### **Alert Preferences**
```
Notification Settings
├─ 🔔 Connection events: ☑️ Show
├─ ⚠️ Security alerts: ☑️ Show
├─ 📊 Performance warnings: ☑️ Show
├─ 🔄 Update notifications: ☑️ Show
├─ ⏰ Notification duration: 5 seconds
└─ 🔊 Sound notifications: ☐ Disabled
```

## 🔧 Troubleshooting

### **Common Connection Issues**

#### **Cannot Connect to VPN**

**Problem**: Connection fails with timeout error
```
Error: Connection timeout (Error Code: 1002)
```

**Solutions**:
1. **Check Internet Connection**
   ```
   1. Disable VPN temporarily
   2. Test internet access
   3. Try different network if available
   ```

2. **Try Different Server**
   ```
   1. Select different server location
   2. Choose server with lower load
   3. Try different protocol (WireGuard → OpenVPN)
   ```

3. **Check Firewall Settings**
   ```
   1. Temporarily disable firewall
   2. Add VPN Hub to firewall exceptions
   3. Allow VPN protocols through firewall
   ```

#### **Authentication Failed**

**Problem**: Invalid credentials error
```
Error: Authentication failed (Error Code: 1001)
```

**Solutions**:
1. **Verify Credentials**
   ```
   1. Check username/email spelling
   2. Ensure password is correct
   3. Try logging into provider website
   ```

2. **Reset Provider Credentials**
   ```
   1. Go to Settings → Providers
   2. Select problematic provider
   3. Click "Update Credentials"
   4. Re-enter login information
   ```

### **Performance Issues**

#### **Slow Connection Speed**

**Problem**: VPN connection significantly slower than normal internet

**Diagnostic Steps**:
```
1. Run speed test without VPN
2. Connect to VPN and run speed test again
3. Try different server locations
4. Test different protocols
```

**Solutions**:
1. **Change Server Location**
   - Choose server closer to your location
   - Select server with lower load percentage
   - Try servers optimized for your use case

2. **Optimize Protocol**
   - WireGuard: Fastest, modern protocol
   - OpenVPN UDP: Good balance of speed and security
   - OpenVPN TCP: Most reliable but slower

#### **High CPU Usage**

**Problem**: VPN Hub using excessive system resources

**Solutions**:
1. **Check Background Processes**
   ```
   1. Open Task Manager (Windows) or Activity Monitor (macOS)
   2. Look for VPN Hub processes
   3. End any stuck or duplicate processes
   ```

2. **Update Application**
   ```
   1. Go to Help → Check for Updates
   2. Download and install latest version
   3. Restart application
   ```

### **Security Issues**

#### **IP/DNS Leak Detected**

**Problem**: Real IP address or DNS queries visible despite VPN connection

**Immediate Actions**:
```
1. Disconnect from VPN immediately
2. Close all browser windows
3. Enable kill switch
4. Reconnect to VPN
```

**Prevention Steps**:
```
1. Enable DNS Leak Protection
2. Disable IPv6 if not needed
3. Use VPN provider's DNS servers
4. Enable kill switch
5. Regularly test for leaks
```

#### **Certificate Errors**

**Problem**: SSL/TLS certificate validation failures

**Solutions**:
1. **Update Certificate Store**
   ```
   1. Go to Settings → Security
   2. Click "Update Certificates"
   3. Restart application
   ```

2. **Check System Time**
   ```
   1. Ensure system date/time is correct
   2. Sync with internet time server
   3. Restart VPN connection
   ```

### **Application Issues**

#### **GUI Not Responding**

**Problem**: Application interface frozen or unresponsive

**Solutions**:
1. **Force Restart**
   ```
   Windows: Ctrl+Alt+Del → Task Manager → End Process
   macOS: Cmd+Option+Esc → Force Quit
   Linux: killall vpn-hub
   ```

2. **Reset Configuration**
   ```
   1. Close VPN Hub completely
   2. Navigate to config directory
   3. Rename config.yaml to config.yaml.backup
   4. Restart application (will create default config)
   ```

#### **Startup Crashes**

**Problem**: Application crashes immediately on startup

**Diagnostic Steps**:
```
1. Check log files in ~/.vpn_hub/logs/
2. Look for error messages
3. Verify Python version compatibility
4. Check dependencies installation
```

**Solutions**:
1. **Reinstall Dependencies**
   ```bash
   pip uninstall -r requirements.txt
   pip install -r requirements.txt
   ```

2. **Run in Debug Mode**
   ```bash
   python src/main.py --debug
   ```

### **Getting Additional Help**

#### **Log Collection for Support**
```bash
# Collect all relevant logs
python src/utils/collect_logs.py --output support_logs.zip

# Include in support request:
# - Log files
# - System information
# - Steps to reproduce issue
# - Expected vs actual behavior
```

#### **Support Channels**
- **Email**: support@vpnhub.local
- **GitHub Issues**: Technical problems and bug reports
- **Documentation**: [docs@vpnhub.local](mailto:docs@vpnhub.local)
- **Emergency Security**: security@vpnhub.local

---

**User Manual Version:** 2.0  
**App Version:** 1.0.6  
**Last Updated:** November 12, 2025  
**For Support:** support@vpnhub.local
