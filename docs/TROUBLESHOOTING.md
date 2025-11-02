# VPN Hub Troubleshooting Guide

Comprehensive troubleshooting guide for VPN Hub enterprise-grade secure VPN manager.

## 📋 Table of Contents

- [Quick Diagnostics](#quick-diagnostics)
- [Connection Issues](#connection-issues)
- [Authentication Problems](#authentication-problems)
- [Performance Issues](#performance-issues)
- [Security Warnings](#security-warnings)
- [Application Errors](#application-errors)
- [Platform-Specific Issues](#platform-specific-issues)
- [Advanced Diagnostics](#advanced-diagnostics)

## 🔍 Quick Diagnostics

### **Initial Troubleshooting Steps**

Before diving into specific issues, try these general steps:

1. **Restart VPN Hub**
   ```
   1. Close VPN Hub completely
   2. Wait 10 seconds
   3. Run as administrator (Windows) or sudo (Linux/macOS)
   4. Check if issue persists
   ```

2. **Check System Requirements**
   ```
   ✅ Python 3.8+ installed
   ✅ PyQt5 dependencies available
   ✅ Administrator/root privileges
   ✅ Stable internet connection
   ✅ 4GB+ RAM available
   ```

3. **Verify Provider Status**
   ```
   1. Check provider's service status page
   2. Test provider's official app
   3. Verify account subscription is active
   4. Check for provider maintenance windows
   ```

### **Log File Locations**

**Windows:**
```
%APPDATA%\VPNHub\logs\
C:\Users\{username}\AppData\Roaming\VPNHub\logs\
```

**macOS:**
```
~/Library/Application Support/VPNHub/logs/
```

**Linux:**
```
~/.local/share/vpnhub/logs/
~/.config/vpnhub/logs/
```

### **Quick Health Check**

```bash
# Run built-in diagnostics
python src/diagnostics/health_check.py

# Check security status
python -c "from src.security.security_monitor import SecurityMonitor; SecurityMonitor().get_security_report()"

# Verify configuration
python -c "from src.config.config_manager import ConfigManager; ConfigManager().validate_config()"
```

## 🔌 Connection Issues

### **Cannot Connect to Any VPN**

#### **Symptoms:**
- All connection attempts fail
- Timeout errors
- "Connection refused" messages

#### **Diagnostic Steps:**
```
1. Test internet connectivity:
   - ping google.com
   - Try browsing without VPN

2. Check firewall settings:
   - Windows: Windows Defender Firewall
   - macOS: System Preferences → Security & Privacy → Firewall
   - Linux: ufw status or iptables -L

3. Test different protocols:
   - Try WireGuard → OpenVPN → IKEv2
   - Check protocol availability per provider

4. Verify DNS resolution:
   - nslookup provider-server.com
   - Try different DNS servers (1.1.1.1, 8.8.8.8)
```

#### **Solutions:**

**Solution 1: Firewall Configuration**
```bash
# Windows Firewall
netsh advfirewall firewall add rule name="VPN Hub" dir=in action=allow program="path\to\python.exe"

# Linux UFW
sudo ufw allow out 1194/udp comment "OpenVPN"
sudo ufw allow out 51820/udp comment "WireGuard"
sudo ufw allow out 500/udp comment "IKEv2"
sudo ufw allow out 4500/udp comment "IKEv2"

# macOS (Terminal)
sudo pfctl -d  # Temporarily disable if testing
```

**Solution 2: Network Interface Issues**
```bash
# Reset network stack (Windows)
netsh winsock reset
netsh int ip reset
ipconfig /flushdns

# Reset network (macOS)
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Reset network (Linux)
sudo systemctl restart NetworkManager
sudo systemctl restart systemd-resolved
```

**Solution 3: Provider-Specific Fixes**
```python
# Reset provider configuration
from src.providers import VPNProviderFactory

provider = VPNProviderFactory.create_provider('nordvpn')
provider.reset_configuration()
provider.refresh_server_list()
```

### **Connection Drops Frequently**

#### **Symptoms:**
- VPN connects but disconnects after a few minutes
- Intermittent connection losses
- Kill switch activates frequently

#### **Diagnostic Steps:**
```
1. Check connection stability:
   - ping -t google.com (continuous ping)
   - Monitor connection for pattern

2. Review logs for errors:
   - Search for "disconnect" or "timeout" in logs
   - Check for network interface changes

3. Test different servers:
   - Try servers with lower load
   - Test servers in different countries
   - Switch protocols if available
```

#### **Solutions:**

**Solution 1: Optimize Connection Settings**
```python
# Adjust timeout and retry settings
CONNECTION_CONFIG = {
    'timeout': 60,  # Increase timeout
    'keepalive': 10,  # More frequent keepalive
    'retry_attempts': 5,  # More retry attempts
    'retry_delay': 5  # Delay between retries
}
```

**Solution 2: Network Adapter Issues**
```bash
# Windows: Reset network adapters
devmgmt.msc  # Device Manager → Network adapters → Disable/Enable

# Update network drivers
# Check manufacturer website for latest drivers
```

**Solution 3: Power Management (Windows)**
```
1. Device Manager → Network adapters
2. Right-click your network adapter
3. Properties → Power Management
4. Uncheck "Allow computer to turn off this device"
```

### **Slow Connection Speeds**

#### **Symptoms:**
- Significant speed reduction with VPN
- Poor streaming/gaming performance
- High latency/ping times

#### **Speed Test Methodology:**
```bash
# Test without VPN (baseline)
speedtest-cli --simple

# Connect to VPN
# Test with VPN
speedtest-cli --simple

# Calculate speed impact
# Expected: 10-30% reduction is normal
# Concerning: >50% reduction needs investigation
```

#### **Speed Optimization:**

**Optimization 1: Server Selection**
```
✅ Choose servers geographically closer
✅ Select servers with <50% load
✅ Try different server providers
✅ Use dedicated/premium servers if available
```

**Optimization 2: Protocol Optimization**
```
Protocol Speed Ranking (fastest to slowest):
1. WireGuard (newest, fastest)
2. OpenVPN UDP (good balance)
3. IKEv2 (good for mobile)
4. OpenVPN TCP (most compatible, slowest)
```

**Optimization 3: System Optimization**
```python
# Disable unnecessary features for speed
SPEED_OPTIMIZED_CONFIG = {
    'kill_switch': True,  # Keep for security
    'dns_leak_protection': True,  # Keep for security
    'ad_blocking': False,  # Disable for speed
    'malware_blocking': False,  # Disable for speed
    'double_vpn': False,  # Disable for speed
    'tor_over_vpn': False  # Disable for speed
}
```

## 🔐 Authentication Problems

### **Login Failed / Invalid Credentials**

#### **Common Causes:**
```
❌ Incorrect username/password
❌ Two-factor authentication required
❌ Account suspended/expired
❌ Special characters in credentials
❌ Copy-paste formatting issues
```

#### **Provider-Specific Authentication:**

**NordVPN:**
```
✅ Use email address as username
✅ Use account password (not service password)
✅ Enable 2FA in account settings
❌ Don't use service credentials for app login
```

**ExpressVPN:**
```
✅ Use activation code (not username/password)
✅ Get fresh code from account dashboard
✅ Activation code is device-specific
❌ Don't reuse expired activation codes
```

**ProtonVPN:**
```
✅ Use OpenVPN credentials (not account login)
✅ Generate OpenVPN credentials in dashboard
✅ OpenVPN password may differ from account password
❌ Don't use account email for OpenVPN login
```

**Surfshark:**
```
✅ Use email address and account password
✅ Enable 2FA for additional security
✅ Password is case-sensitive
❌ Don't use service credentials
```

**CyberGhost:**
```
✅ Use username (not email) for some plans
✅ Check subscription level for feature access
✅ Use account password
❌ Don't confuse username with email
```

#### **Authentication Troubleshooting:**

**Step 1: Verify Credentials**
```
1. Log into provider's website
2. Reset password if uncertain
3. Generate new credentials if applicable
4. Check for account notifications/emails
```

**Step 2: Clear Stored Credentials**
```python
# Clear stored credentials and re-enter
from src.security.credential_manager import CredentialManager

cred_manager = CredentialManager()
cred_manager.delete_credentials('provider_name')
# Re-enter credentials in VPN Hub
```

**Step 3: Account Verification**
```
1. Check subscription status
2. Verify payment/billing status
3. Check for account limitations
4. Contact provider support if needed
```

### **Two-Factor Authentication Issues**

#### **Symptoms:**
- Authentication fails despite correct credentials
- No 2FA prompt appears
- 2FA codes rejected

#### **Solutions:**

**Solution 1: Time Synchronization**
```bash
# Ensure system time is accurate
# Windows
w32tm /resync

# macOS
sudo sntp -sS time.apple.com

# Linux
sudo ntpdate -s time.nist.gov
```

**Solution 2: 2FA App Issues**
```
1. Regenerate 2FA secret in provider account
2. Re-add to authenticator app
3. Use backup codes if available
4. Try different authenticator app
```

## ⚡ Performance Issues

### **High CPU Usage**

#### **Symptoms:**
- VPN Hub using >20% CPU constantly
- System becomes slow/unresponsive
- Fan noise increases

#### **Diagnostic Steps:**
```python
# Monitor resource usage
import psutil
import os

process = psutil.Process(os.getpid())
print(f"CPU: {process.cpu_percent()}%")
print(f"Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB")
print(f"Threads: {process.num_threads()}")
```

#### **Solutions:**

**Solution 1: Reduce Update Frequency**
```python
# Increase status update intervals
STATUS_UPDATE_CONFIG = {
    'connection_check': 60,  # Check every 60 seconds
    'server_refresh': 300,   # Refresh servers every 5 minutes
    'security_scan': 900     # Security scan every 15 minutes
}
```

**Solution 2: Disable Resource-Intensive Features**
```python
# Disable features for performance
PERFORMANCE_CONFIG = {
    'real_time_monitoring': False,
    'continuous_security_scan': False,
    'automatic_server_optimization': False,
    'detailed_connection_logging': False
}
```

### **High Memory Usage**

#### **Symptoms:**
- VPN Hub using >500MB RAM
- System memory warnings
- Application becomes sluggish

#### **Memory Optimization:**
```python
# Clean up resources periodically
import gc

def cleanup_resources():
    """Periodic memory cleanup"""
    gc.collect()  # Force garbage collection
    
    # Clear caches
    server_cache.clear()
    connection_history.cleanup_old_entries()
    
    # Reset large objects
    if len(log_buffer) > 1000:
        log_buffer = log_buffer[-500:]  # Keep only recent logs
```

## 🛡️ Security Warnings

### **SSL/TLS Certificate Errors**

#### **Error Messages:**
```
Certificate verification failed
SSL handshake failed
Untrusted certificate
Certificate has expired
```

#### **Solutions:**

**Solution 1: Update Certificate Store**
```bash
# Update system certificates
# Windows
certlm.msc  # Certificate Manager

# macOS
# System updates automatically

# Linux (Ubuntu/Debian)
sudo apt update && sudo apt install ca-certificates
```

**Solution 2: Time/Date Issues**
```bash
# Ensure system time is correct
# SSL certificates are time-sensitive
```

**Solution 3: Certificate Pinning Issues**
```python
# Temporarily disable certificate pinning for testing
SECURITY_CONFIG = {
    'certificate_pinning': False,  # Temporary
    'tls_verification': True,      # Keep enabled
    'hostname_verification': True  # Keep enabled
}
```

### **DNS Leak Detected**

#### **Symptoms:**
- Real DNS servers visible in leak tests
- ISP DNS queries despite VPN connection
- Geographic location not matching VPN

#### **DNS Leak Test:**
```bash
# Test for DNS leaks
# Method 1: Command line
nslookup google.com
# Should show VPN provider's DNS

# Method 2: Online test
# Visit: dnsleaktest.com, ipleak.net
```

#### **Fix DNS Leaks:**

**Solution 1: Force VPN DNS**
```python
DNS_CONFIG = {
    'use_vpn_dns': True,
    'block_system_dns': True,
    'custom_dns': ['1.1.1.1', '8.8.8.8'],  # Fallback
    'dns_over_https': True
}
```

**Solution 2: IPv6 Disable**
```bash
# Disable IPv6 to prevent leaks
# Windows
netsh interface ipv6 set global randomizeidentifiers=disabled
netsh interface ipv6 set privacy state=disabled

# Linux
echo 1 | sudo tee /proc/sys/net/ipv6/conf/all/disable_ipv6
```

**Solution 3: Flush DNS Cache**
```bash
# Clear DNS cache
# Windows
ipconfig /flushdns

# macOS
sudo dscacheutil -flushcache

# Linux
sudo systemctl flush-dns
```

### **Kill Switch Not Working**

#### **Test Kill Switch:**
```bash
# Test procedure:
1. Connect to VPN
2. Manually disconnect (simulate drop)
3. Try to access internet
4. Should be blocked
```

#### **Fix Kill Switch:**

**Solution 1: Enable System-Level Kill Switch**
```python
KILL_SWITCH_CONFIG = {
    'enabled': True,
    'method': 'firewall',  # Use system firewall
    'block_ipv6': True,
    'allow_lan': False,
    'strict_mode': True
}
```

**Solution 2: Firewall Rules**
```bash
# Manual firewall configuration
# Windows
netsh advfirewall firewall add rule name="Block All Internet" dir=out action=block

# Linux (iptables)
sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -o tun+ -j ACCEPT  # Allow VPN interface
```

## 🖥️ Application Errors

### **Startup Crashes**

#### **Error Messages:**
```
Python.exe has stopped working
ImportError: No module named 'PyQt5'
AttributeError: module has no attribute
```

#### **Solutions:**

**Solution 1: Dependency Issues**
```bash
# Reinstall dependencies
pip uninstall -r requirements.txt -y
pip install -r requirements.txt

# Check for conflicts
pip check
```

**Solution 2: Python Version**
```bash
# Verify Python version
python --version
# Should be 3.8+

# Check PyQt5 installation
python -c "import PyQt5; print(PyQt5.QtCore.PYQT_VERSION_STR)"
```

**Solution 3: Run in Debug Mode**
```bash
# Get detailed error information
python src/main.py --debug --verbose

# Check logs
tail -f ~/.vpnhub/logs/error.log
```

### **GUI Not Responding**

#### **Symptoms:**
- Window freezes
- Buttons don't respond
- Application hangs

#### **Solutions:**

**Solution 1: Kill Hung Process**
```bash
# Windows
tasklist | findstr python
taskkill /PID <process_id> /F

# macOS/Linux
ps aux | grep vpn
kill -9 <process_id>
```

**Solution 2: Reset Configuration**
```bash
# Backup and reset config
mv ~/.vpnhub/config.yaml ~/.vpnhub/config.yaml.backup
# Restart VPN Hub (will create default config)
```

**Solution 3: Safe Mode Start**
```bash
# Start with minimal configuration
python src/main.py --safe-mode --no-plugins
```

### **System Tray Issues**

#### **Symptoms:**
- No system tray icon
- Icon not clickable
- Menu doesn't appear

#### **Solutions:**

**Solution 1: System Tray Availability**
```python
# Check if system tray is available
from PyQt5.QtWidgets import QSystemTrayIcon
if not QSystemTrayIcon.isSystemTrayAvailable():
    print("System tray not available")
```

**Solution 2: Icon File Issues**
```bash
# Regenerate icon files
python create_icon.py

# Check icon files exist
ls -la assets/vpn_hub_icon*.png
```

**Solution 3: Desktop Environment**
```bash
# Linux: Ensure system tray support
# GNOME: Install gnome-shell-extension-appindicator
# KDE: Should work by default
# XFCE: Check panel settings
```

## 🔧 Platform-Specific Issues

### **Windows Issues**

#### **UAC Prompts**
```
Problem: Constant UAC prompts
Solution: Run as administrator once, then use scheduled task
```

#### **Windows Defender**
```
Problem: Windows Defender blocking VPN Hub
Solution: Add exclusion for VPN Hub folder
```

#### **Network Adapter Issues**
```bash
# Reset network adapters
netsh winsock reset
netsh int ip reset all
netsh winhttp reset proxy
```

### **macOS Issues**

#### **Permission Denied**
```bash
# Grant full disk access
System Preferences → Security & Privacy → Full Disk Access
Add VPN Hub or Terminal
```

#### **Keychain Access**
```bash
# Reset keychain if credential issues
security delete-generic-password -s "VPN Hub"
# Re-enter credentials
```

### **Linux Issues**

#### **Permission Issues**
```bash
# Add user to necessary groups
sudo usermod -a -G netdev $USER
sudo usermod -a -G vpn $USER

# Grant network configuration permissions
sudo setcap cap_net_admin+ep /usr/bin/python3
```

#### **NetworkManager Conflicts**
```bash
# Configure NetworkManager to ignore VPN interfaces
echo "[keyfile]
unmanaged-devices=interface-name:tun*;interface-name:tap*" | sudo tee -a /etc/NetworkManager/NetworkManager.conf

sudo systemctl restart NetworkManager
```

## 🔬 Advanced Diagnostics

### **Network Traffic Analysis**

#### **Capture VPN Traffic:**
```bash
# Monitor VPN interface traffic
# Linux/macOS
sudo tcpdump -i tun0 -w vpn_traffic.pcap

# Windows
# Use Wireshark or netsh trace
netsh trace start capture=yes tracefile=vpn_trace.etl
# (Stop with: netsh trace stop)
```

#### **Analyze Connection Patterns:**
```python
# Log connection patterns
import time
import requests

def test_connection_stability():
    """Test connection stability over time"""
    for i in range(60):  # Test for 1 hour
        try:
            response = requests.get('http://httpbin.org/ip', timeout=10)
            ip = response.json()['origin']
            print(f"{time.strftime('%H:%M:%S')} - IP: {ip}")
        except Exception as e:
            print(f"{time.strftime('%H:%M:%S')} - Error: {e}")
        time.sleep(60)  # Check every minute
```

### **Performance Profiling**

#### **Memory Profiling:**
```bash
# Install memory profiler
pip install memory-profiler

# Profile memory usage
python -m memory_profiler src/main.py
```

#### **CPU Profiling:**
```python
# Profile CPU usage
import cProfile
import pstats

profiler = cProfile.Profile()
profiler.enable()
# Run VPN Hub operations
profiler.disable()

stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)  # Top 20 functions
```

### **Debug Logging**

#### **Enable Verbose Logging:**
```python
# Set debug logging level
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler()
    ]
)
```

#### **Network Debug:**
```bash
# Enable network debugging
export PYTHONHTTPSVERIFY=0  # Disable SSL verification for debugging
export VPN_HUB_DEBUG=1      # Enable VPN Hub debug mode
export VPN_HUB_VERBOSE=1    # Enable verbose output
```

## 📞 Getting Help

### **Collect Diagnostic Information**

Before contacting support, collect this information:

```bash
# System information
python -c "import platform; print(platform.platform())"
python --version
pip list | grep -E "(PyQt5|requests|cryptography)"

# VPN Hub version
python -c "from src import __version__; print(__version__)"

# Network configuration
ipconfig /all  # Windows
ifconfig       # macOS/Linux

# Recent logs
tail -50 ~/.vpnhub/logs/error.log
tail -50 ~/.vpnhub/logs/connection.log
```

### **Support Channels**

#### **Community Support**
- **GitHub Issues**: Bug reports and feature requests
- **Community Forum**: General questions and discussions
- **Reddit**: r/VPNHub community support

#### **Direct Support**
- **Email**: support@vpnhub.local
- **Technical Support**: tech-support@vpnhub.local
- **Security Issues**: security@vpnhub.local

#### **Emergency Support**
- **Critical Security Issues**: security-emergency@vpnhub.local
- **Data Breach Concerns**: incident-response@vpnhub.local

### **Creating Effective Support Requests**

Include this information in your support request:

```
1. Problem Description:
   - What you were trying to do
   - What happened instead
   - When the problem started

2. System Information:
   - Operating system and version
   - Python version
   - VPN Hub version

3. Steps to Reproduce:
   - Detailed steps to recreate the issue
   - Whether it's consistent or intermittent

4. Error Messages:
   - Exact error messages (copy/paste)
   - Screenshots if relevant

5. Diagnostic Information:
   - Log files (last 50 lines)
   - Network configuration
   - Any troubleshooting already attempted

6. Impact:
   - How severely this affects your usage
   - Any workarounds you've found
```

---

**Troubleshooting Guide Version:** 2.0  
**Last Updated:** November 1, 2025  
**For Support:** troubleshooting@vpnhub.local