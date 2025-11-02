# VPN Hub Provider Setup Guide

Step-by-step guide for setting up all supported VPN providers in VPN Hub.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [NordVPN Setup](#nordvpn-setup)
- [ExpressVPN Setup](#expressvpn-setup)
- [Surfshark Setup](#surfshark-setup)
- [CyberGhost Setup](#cyberghost-setup)
- [ProtonVPN Setup](#protonvpn-setup)
- [Provider Comparison](#provider-comparison)
- [Troubleshooting](#troubleshooting)

## 📋 Prerequisites

### **Before You Begin**

1. **Active VPN Subscription**
   - Ensure you have an active subscription with your chosen provider
   - Verify your account is in good standing
   - Check your subscription includes the features you need

2. **VPN Hub Requirements**
   - VPN Hub application installed and running
   - Administrative privileges on your system
   - Stable internet connection for initial setup

3. **Account Information Ready**
   - Provider login credentials
   - Two-factor authentication codes (if enabled)
   - Activation codes or special credentials (provider-specific)

### **General Setup Process**

All providers follow this basic setup flow:
```
1. Add Provider → 2. Enter Credentials → 3. Test Connection → 4. Configure Features → 5. Save Settings
```

## 🔵 NordVPN Setup

### **Account Preparation**

1. **Verify Subscription**
   - Log into [nordvpn.com](https://nordvpn.com)
   - Ensure your subscription is active
   - Note your plan type (affects available features)

2. **Enable Two-Factor Authentication (Recommended)**
   ```
   1. Go to Account Settings
   2. Enable Two-Factor Authentication
   3. Use Google Authenticator or similar app
   4. Save backup codes securely
   ```

### **VPN Hub Configuration**

#### **Step 1: Add NordVPN Provider**
```
1. Open VPN Hub
2. Click "Add Provider" or go to Settings → Providers
3. Select "NordVPN" from the list
4. Click "Configure"
```

#### **Step 2: Enter Credentials**
```
Provider: NordVPN
├─ Username: your@email.com
├─ Password: your_account_password
├─ Two-Factor: [Enter if prompted]
└─ Server Protocol: Auto (recommended)
```

#### **Step 3: Test Connection**
```
1. Click "Test Connection"
2. Wait for authentication (10-30 seconds)
3. Verify successful connection message
4. Check assigned IP address
```

#### **Step 4: Configure NordVPN Features**

**Basic Security Features:**
```
NordVPN Security Settings
├─ 🛡️ Kill Switch: ☑️ Enabled
├─ 🔒 DNS Leak Protection: ☑️ Enabled
├─ 🚫 CyberSec (Ad Blocking): ☑️ Enabled
├─ 🔄 Auto-Connect: ☐ Optional
└─ 🌐 Custom DNS: Use NordVPN DNS
```

**Advanced Features:**
```
Advanced NordVPN Settings
├─ 🧅 Onion Over VPN: ☐ Available for specific servers
├─ 📺 P2P Servers: ☑️ Auto-select for torrenting
├─ 🎯 Dedicated IP: ☐ If purchased separately
├─ 🚀 NordLynx (WireGuard): ☑️ Preferred protocol
└─ 🔐 Double VPN: ☐ Maximum security option
```

**Server Selection Preferences:**
```
Server Preferences
├─ 🌍 Region: Auto-select optimal
├─ 🏙️ City Preference: Nearest major city
├─ 📊 Load Balancing: Prefer lower load servers
├─ 🎯 Special Servers: 
│   ├─ P2P optimized
│   ├─ Streaming optimized
│   └─ Onion over VPN
└─ 🔄 Protocol: NordLynx (WireGuard)
```

#### **Step 5: Save and Verify**
```
1. Click "Save Configuration"
2. Perform connection test
3. Run IP leak test to verify security
4. Test kill switch functionality
```

## 🟠 ExpressVPN Setup

### **Account Preparation**

1. **Get Activation Code**
   ```
   1. Log into expressvpn.com account
   2. Go to "Set up on more devices"
   3. Copy the activation code (different from login password)
   4. Note: This code is specific to VPN applications
   ```

2. **Subscription Verification**
   - Verify active subscription status
   - Check available simultaneous connections
   - Note any regional restrictions

### **VPN Hub Configuration**

#### **Step 1: Add ExpressVPN Provider**
```
1. Open VPN Hub
2. Add Provider → ExpressVPN
3. Select "Configure ExpressVPN"
```

#### **Step 2: Activation Process**
```
Provider: ExpressVPN
├─ Activation Method: Activation Code
├─ Activation Code: [Paste from account dashboard]
├─ Email: your@email.com (optional, for support)
└─ Region: [Auto-detected or manual selection]
```

**Important**: ExpressVPN uses activation codes, not username/password for app authentication.

#### **Step 3: Protocol Selection**
```
ExpressVPN Protocol Options
├─ 🚀 Lightway (Recommended)
│   ├─ Fastest speeds
│   ├─ Lowest battery usage
│   └─ Most reliable connections
├─ 🔒 OpenVPN UDP
│   ├─ Good balance of speed/security
│   └─ Works on most networks
├─ 🛡️ OpenVPN TCP
│   ├─ Most reliable for unstable networks
│   └─ Slower but more stable
└─ ⚡ IKEv2
    ├─ Fast reconnection
    └─ Good for mobile devices
```

#### **Step 4: Configure ExpressVPN Features**

**Security Settings:**
```
ExpressVPN Security
├─ 🛡️ Network Lock (Kill Switch): ☑️ Enabled
├─ 🔒 DNS Leak Protection: ☑️ Auto-enabled
├─ 🌐 Smart Location: ☑️ Auto-select optimal server
├─ 🔄 Auto-Reconnect: ☑️ Enabled
└─ 📱 Split Tunneling: ☐ Configure if needed
```

**Split Tunneling Configuration:**
```
Split Tunneling Options
├─ 🌐 Route All Traffic Through VPN: Default
├─ 📱 Exclude Specific Apps:
│   ├─ Banking apps
│   ├─ Local network apps
│   └─ Gaming applications
└─ 🎯 VPN Only Specific Apps:
    ├─ Browsers
    ├─ Streaming apps
    └─ P2P applications
```

#### **Step 5: Smart Location Setup**
```
Smart Location Preferences
├─ 🎯 Optimize For: Speed (default)
├─ 🌍 Preferred Regions: 
│   ├─ North America
│   ├─ Europe
│   └─ Asia-Pacific
├─ 📊 Load Balancing: Automatic
└─ 🔄 Fallback Servers: 3 alternatives
```

## 🦈 Surfshark Setup

### **Account Preparation**

1. **Credentials Ready**
   - Your Surfshark email address
   - Account password
   - Two-factor authentication setup (recommended)

2. **Subscription Features**
   - Unlimited simultaneous connections
   - CleanWeb (ad-blocking) available
   - Whitelister (split tunneling) included

### **VPN Hub Configuration**

#### **Step 1: Add Surfshark Provider**
```
1. VPN Hub → Add Provider
2. Select "Surfshark"
3. Begin configuration process
```

#### **Step 2: Authentication**
```
Provider: Surfshark
├─ Email: your@email.com
├─ Password: your_account_password
├─ Two-Factor: [If enabled]
└─ Server Selection: Auto-optimal
```

#### **Step 3: Configure Surfshark Features**

**Core Security Features:**
```
Surfshark Security
├─ 🛡️ Kill Switch: ☑️ Enabled
├─ 🌐 CleanWeb (Ad Blocking): ☑️ Enabled
├─ 🔒 DNS Leak Protection: ☑️ Auto-enabled
├─ 🚫 Malware Blocking: ☑️ Enabled
└─ 🔄 Auto-Connect: ☐ Optional
```

**Advanced Features:**
```
Advanced Surfshark Settings
├─ 🎯 Whitelister (Split Tunneling):
│   ├─ Bypass VPN for specific apps
│   ├─ Bypass VPN for websites
│   └─ VPN only for selected apps
├─ 🌍 MultiHop (Double VPN):
│   ├─ Connect through 2 countries
│   ├─ Enhanced privacy protection
│   └─ Slower but more secure
├─ 📱 NoBorders Mode:
│   ├─ For restrictive networks
│   ├─ Bypasses VPN blocking
│   └─ Automatic activation option
└─ 🔐 Camouflage Mode:
    ├─ Hides VPN usage from ISP
    ├─ OpenVPN with obfuscation
    └─ For maximum stealth
```

**Whitelister Configuration:**
```
Split Tunneling Setup
├─ 🌐 Route Mode: All traffic through VPN (default)
├─ 📱 Bypass Apps:
│   ├─ Add applications to exclude
│   ├─ Local network applications
│   └─ Banking/financial apps
├─ 🌍 Bypass Websites:
│   ├─ Local news sites
│   ├─ Regional services
│   └─ Speed-sensitive sites
└─ 🎯 VPN Only Mode:
    ├─ Only specified apps use VPN
    ├─ All other traffic direct
    └─ Useful for specific security needs
```

#### **Step 4: Protocol and Server Settings**
```
Connection Settings
├─ 🔄 Protocol: WireGuard (recommended)
├─ 🌍 Server Selection: 
│   ├─ Fastest server (auto)
│   ├─ Specific country
│   ├─ Streaming optimized
│   └─ P2P optimized
├─ 📊 Load Balancing: Automatic
└─ 🔄 Reconnection: 3 attempts
```

## 👻 CyberGhost Setup

### **Account Preparation**

1. **Account Information**
   - CyberGhost username (not email)
   - Account password
   - Subscription plan level

2. **Feature Availability**
   - Server access based on subscription
   - Streaming servers (premium feature)
   - Torrenting servers included

### **VPN Hub Configuration**

#### **Step 1: Add CyberGhost Provider**
```
1. VPN Hub → Providers → Add New
2. Select "CyberGhost VPN"
3. Start configuration wizard
```

#### **Step 2: Credentials Entry**
```
Provider: CyberGhost
├─ Username: cyberghost_username (not email)
├─ Password: your_password
├─ Plan Level: Auto-detected
└─ Server Access: Based on subscription
```

#### **Step 3: Server Specialization**

**Choose Primary Use Case:**
```
CyberGhost Server Types
├─ 🌐 General Browsing:
│   ├─ Standard servers
│   ├─ Optimized for web browsing
│   └─ Balanced speed/security
├─ 📺 Streaming:
│   ├─ Netflix, Hulu, BBC iPlayer
│   ├─ Geo-unblocking optimized
│   └─ High-speed streaming servers
├─ 📁 Torrenting:
│   ├─ P2P optimized servers
│   ├─ No bandwidth limits
│   └─ Enhanced privacy protection
└─ 🎮 Gaming:
    ├─ Low latency servers
    ├─ DDoS protection
    └─ Optimized routing
```

#### **Step 4: Configure Security Features**

**Standard Security:**
```
CyberGhost Security
├─ 🛡️ Automatic Kill Switch: ☑️ Enabled
├─ 🔒 DNS Leak Protection: ☑️ Auto-enabled
├─ 🚫 Malware Blocking: ☑️ Enabled
├─ 🌐 IPv6 Leak Protection: ☑️ Enabled
└─ 🔄 Auto-Connect: ☐ Optional
```

**Advanced Security:**
```
Advanced CyberGhost Features
├─ 🔐 WiFi Protection:
│   ├─ Auto-connect on public WiFi
│   ├─ Untrusted network detection
│   └─ Automatic security activation
├─ 📊 Data Compression:
│   ├─ Reduce bandwidth usage
│   ├─ Faster loading on slow connections
│   └─ Mobile data savings
├─ 🎯 Smart Rules:
│   ├─ Auto-connect by location
│   ├─ App-specific connections
│   └─ Time-based automation
└─ 🌍 NoSpy Servers:
    ├─ Premium feature
    ├─ CyberGhost owned/operated
    └─ Maximum privacy protection
```

#### **Step 5: Streaming Configuration**

**Streaming Services Setup:**
```
Streaming Optimization
├─ 📺 Netflix:
│   ├─ US Netflix servers
│   ├─ UK Netflix servers
│   └─ Other regions available
├─ 🎬 Other Services:
│   ├─ Hulu, Amazon Prime
│   ├─ BBC iPlayer, ITV Hub
│   ├─ Disney+, HBO Max
│   └─ Regional streaming platforms
├─ 🔄 Auto-Selection:
│   ├─ Detect streaming apps
│   ├─ Auto-connect to optimal server
│   └─ Seamless switching
└─ 📊 Performance Monitoring:
    ├─ Connection speed testing
    ├─ Streaming quality optimization
    └─ Server load balancing
```

## 🔒 ProtonVPN Setup

### **Account Preparation**

1. **OpenVPN Credentials**
   ```
   Important: ProtonVPN uses separate OpenVPN credentials
   
   1. Log into account.protonvpn.com
   2. Go to "Account" → "OpenVPN/IKEv2 username"
   3. Note the OpenVPN username (different from email)
   4. Use the OpenVPN password (may be same as account password)
   ```

2. **Subscription Tier**
   - Free: Limited servers and features
   - Basic: Standard servers, moderate speed
   - Plus: High-speed servers, Secure Core, streaming
   - Visionary: All features, ProtonMail included

### **VPN Hub Configuration**

#### **Step 1: Add ProtonVPN Provider**
```
1. VPN Hub → Add Provider
2. Select "ProtonVPN"
3. Choose configuration type: OpenVPN/WireGuard
```

#### **Step 2: Authentication Setup**
```
Provider: ProtonVPN
├─ Protocol: WireGuard (recommended) or OpenVPN
├─ Username: openvpn_username (from account dashboard)
├─ Password: openvpn_password
├─ Plan Level: Auto-detected from account
└─ Server Tier: Based on subscription
```

#### **Step 3: Configure ProtonVPN Features**

**Core Security Features:**
```
ProtonVPN Security
├─ 🛡️ Kill Switch: ☑️ Enabled
├─ 🔒 DNS Leak Protection: ☑️ Auto-enabled
├─ 🌐 IPv6 Leak Protection: ☑️ Enabled
├─ 🚫 NetShield (Ad/Tracker Blocking): ☑️ If available
└─ 🔄 Auto-Connect: ☐ Optional
```

**Advanced Privacy Features:**
```
ProtonVPN Advanced Features
├─ 🛡️ Secure Core:
│   ├─ Route through privacy-friendly countries
│   ├─ Double-hop for maximum security
│   ├─ Plus/Visionary plans only
│   └─ Slower but most secure option
├─ 🧅 Tor over VPN:
│   ├─ Access .onion sites directly
│   ├─ Enhanced anonymity
│   ├─ Automatic Tor routing
│   └─ Specialized servers
├─ 📺 Streaming Support:
│   ├─ Plus servers for streaming
│   ├─ Netflix, Disney+, etc.
│   ├─ Optimized for video quality
│   └─ Geographic content access
└─ ⚡ P2P Support:
    ├─ Dedicated P2P servers
    ├─ Port forwarding available
    ├─ No bandwidth restrictions
    └─ Enhanced privacy for torrenting
```

#### **Step 4: Secure Core Configuration**

**Secure Core Setup (Plus/Visionary Plans):**
```
Secure Core Options
├─ 🌍 Entry Countries:
│   ├─ Switzerland (ProtonVPN owned)
│   ├─ Iceland (strong privacy laws)
│   └─ Sweden (secure infrastructure)
├─ 🎯 Exit Countries:
│   ├─ Any country in server network
│   ├─ Optimized routing
│   └─ Maintained anonymity
├─ 🔄 Auto-Selection:
│   ├─ Optimal Secure Core route
│   ├─ Load balancing
│   └─ Performance optimization
└─ ⚡ Performance Impact:
    ├─ 20-30% speed reduction expected
    ├─ Enhanced security trade-off
    └─ Best for high-risk scenarios
```

#### **Step 5: NetShield Configuration**

**Ad and Tracker Blocking:**
```
NetShield Settings
├─ 🚫 Block Malware:
│   ├─ Known malicious domains
│   ├─ Phishing sites
│   └─ Malware distribution
├─ 📊 Block Trackers:
│   ├─ Advertising trackers
│   ├─ Analytics scripts
│   └─ Social media trackers
├─ 🎯 Block Ads:
│   ├─ Display advertisements
│   ├─ Video ads (partial)
│   └─ Popup ads
└─ 🔄 Custom Lists:
    ├─ Import custom blocklists
    ├─ Whitelist trusted domains
    └─ Advanced filtering rules
```

## 📊 Provider Comparison

### **Feature Comparison Matrix**

| Feature | NordVPN | ExpressVPN | Surfshark | CyberGhost | ProtonVPN |
|---------|---------|------------|-----------|------------|-----------|
| **Security** |
| Kill Switch | ✅ | ✅ | ✅ | ✅ | ✅ |
| DNS Leak Protection | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ad Blocking | ✅ CyberSec | ❌ | ✅ CleanWeb | ✅ | ✅ NetShield |
| Double VPN | ✅ | ❌ | ✅ MultiHop | ❌ | ✅ Secure Core |
| Tor Support | ✅ Onion Over VPN | ❌ | ❌ | ❌ | ✅ Tor over VPN |
| **Performance** |
| WireGuard | ✅ NordLynx | ❌ | ✅ | ✅ | ✅ |
| Lightway | ❌ | ✅ | ❌ | ❌ | ❌ |
| Server Count | 5,500+ | 3,000+ | 3,200+ | 7,000+ | 1,700+ |
| **Features** |
| Split Tunneling | ✅ | ✅ | ✅ Whitelister | ✅ | ❌ |
| Streaming Support | ✅ | ✅ | ✅ | ✅ Dedicated | ✅ Plus/Visionary |
| P2P Support | ✅ | ✅ | ✅ | ✅ | ✅ |
| Simultaneous Connections | 6 | 5 | Unlimited | 7 | 10 |
| **Unique Features** |
| Specialty | CyberSec, P2P | Smart Location | CleanWeb, Unlimited | Gaming, Streaming | Secure Core, Open Source |

### **Setup Complexity Rating**

| Provider | Complexity | Setup Time | Unique Requirements |
|----------|------------|------------|-------------------|
| **Surfshark** | ⭐ Easy | 2-3 minutes | Standard email/password |
| **NordVPN** | ⭐⭐ Easy | 3-5 minutes | Account credentials |
| **CyberGhost** | ⭐⭐ Moderate | 5-7 minutes | Username (not email) |
| **ExpressVPN** | ⭐⭐⭐ Moderate | 5-8 minutes | Activation code required |
| **ProtonVPN** | ⭐⭐⭐⭐ Complex | 8-10 minutes | Separate OpenVPN credentials |

### **Recommended Use Cases**

#### **Best for Beginners**
**Surfshark**
- Unlimited connections
- Simple setup process
- Comprehensive features
- Competitive pricing

#### **Best for Streaming**
**ExpressVPN** or **CyberGhost**
- Dedicated streaming servers
- Reliable geo-unblocking
- High-speed connections
- Proven track record

#### **Best for Security**
**ProtonVPN** or **NordVPN**
- Advanced security features
- No-logs audited policies
- Strong encryption standards
- Privacy-focused jurisdictions

#### **Best for Families**
**Surfshark** or **CyberGhost**
- Multiple simultaneous connections
- User-friendly interfaces
- Parental control features
- Good value for money

## 🔧 Troubleshooting

### **Common Setup Issues**

#### **Authentication Problems**

**NordVPN Authentication Fails**
```
Error: "Login failed" or "Invalid credentials"

Solutions:
1. Verify email and password on nordvpn.com
2. Check for 2FA requirements
3. Reset password if necessary
4. Contact NordVPN support for account issues
```

**ExpressVPN Activation Code Issues**
```
Error: "Invalid activation code" or "Code already used"

Solutions:
1. Get fresh activation code from account dashboard
2. Ensure code is copied completely (no extra spaces)
3. Try different device/location for activation
4. Contact ExpressVPN for new activation code
```

**ProtonVPN OpenVPN Credentials**
```
Error: "Authentication failed" with correct account password

Solutions:
1. Generate new OpenVPN credentials in account dashboard
2. Use OpenVPN username (not email)
3. Use OpenVPN password (may differ from account password)
4. Check subscription level for server access
```

#### **Connection Issues**

**Cannot Connect to Any Server**
```
Symptoms: All servers fail to connect, timeout errors

Diagnostic Steps:
1. Test internet connection without VPN
2. Try different protocols (WireGuard → OpenVPN)
3. Check firewall settings
4. Verify provider service status
5. Try different server locations

Common Solutions:
- Temporarily disable antivirus/firewall
- Run VPN Hub as administrator
- Check for ISP VPN blocking
- Update provider client software
```

**Slow Connection Speeds**
```
Symptoms: Significantly reduced speed with VPN

Optimization Steps:
1. Test speed without VPN (baseline)
2. Try servers closer to your location
3. Switch to faster protocol (WireGuard)
4. Choose servers with lower load
5. Disable unnecessary features (Double VPN, etc.)

Speed Optimization:
- Use WireGuard when available
- Select servers in nearby countries
- Avoid peak usage times
- Consider different provider servers
```

#### **Feature-Specific Issues**

**Kill Switch Not Working**
```
Problem: Internet continues working when VPN disconnects

Solutions:
1. Verify kill switch is enabled in settings
2. Test by manually disconnecting VPN
3. Check for WebRTC leaks in browser
4. Configure application-level kill switch
5. Use provider's native kill switch if available
```

**DNS Leaks Detected**
```
Problem: Real DNS servers visible despite VPN connection

Fixes:
1. Enable DNS leak protection in settings
2. Use provider's DNS servers
3. Disable IPv6 if causing leaks
4. Clear DNS cache after connecting
5. Use alternative DNS leak test sites
```

**Split Tunneling Not Working**
```
Problem: Apps not following split tunnel rules

Solutions:
1. Restart affected applications after VPN connection
2. Clear application cache/data
3. Check application permissions
4. Verify split tunnel configuration
5. Use provider's official client for comparison
```

### **Provider-Specific Troubleshooting**

#### **NordVPN Issues**
- **CyberSec not blocking ads**: Clear browser cache, disable other ad blockers
- **P2P servers not working**: Verify subscription includes P2P access
- **Onion over VPN slow**: Expected behavior, try different exit servers

#### **ExpressVPN Issues**
- **Lightway connection fails**: Fall back to OpenVPN, check for updates
- **Smart Location not optimal**: Manually select servers, report feedback
- **Split tunneling limited**: Feature availability varies by platform

#### **Surfshark Issues**
- **CleanWeb inconsistent**: Update filter lists, check domain whitelists
- **MultiHop very slow**: Expected performance impact, try different combinations
- **NoBorders mode needed**: Enable for restrictive networks

#### **CyberGhost Issues**
- **Streaming servers blocked**: Try different streaming servers, clear cookies
- **NoSpy servers unavailable**: Check subscription level, upgrade if needed
- **Gaming servers high ping**: Try different game server locations

#### **ProtonVPN Issues**
- **Secure Core very slow**: Expected behavior, disable for normal use
- **Tor over VPN not working**: Check Tor browser settings, verify server support
- **NetShield blocking wanted content**: Whitelist specific domains

### **Getting Additional Help**

#### **Provider Support Contacts**
- **NordVPN**: support@nordvpn.com, Live chat available
- **ExpressVPN**: support@expressvpn.com, 24/7 live chat
- **Surfshark**: support@surfshark.com, Live chat and email
- **CyberGhost**: support@cyberghostvpn.com, 24/7 support
- **ProtonVPN**: contact@protonvpn.com, Email support

#### **VPN Hub Support**
- **General Setup**: setup-help@vpnhub.local
- **Technical Issues**: tech-support@vpnhub.local
- **Provider Integration**: provider-support@vpnhub.local

---

**Provider Setup Guide Version:** 2.0  
**Last Updated:** November 1, 2025  
**For Support:** provider-setup@vpnhub.local