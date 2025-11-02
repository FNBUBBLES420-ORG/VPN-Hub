# VPN Hub API Reference

Complete API documentation for VPN Hub enterprise-grade secure VPN manager.

## 📋 Table of Contents

- [Core API](#core-api)
- [Provider APIs](#provider-apis)
- [Security APIs](#security-apis)
- [Configuration APIs](#configuration-apis)
- [Monitoring APIs](#monitoring-apis)
- [Utility APIs](#utility-apis)

## 🔌 Core API

### **VPNManager Class**

The main interface for VPN operations.

```python
from src.core.vpn_manager import VPNManager

# Initialize VPN Manager
vpn_manager = VPNManager()
```

#### **Methods**

##### `connect(provider: str, server: str = None) -> bool`
Connect to a VPN provider.

**Parameters:**
- `provider` (str): Provider name ('nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'protonvpn')
- `server` (str, optional): Specific server to connect to

**Returns:**
- `bool`: True if connection successful, False otherwise

**Example:**
```python
# Connect to NordVPN (auto-select server)
success = await vpn_manager.connect('nordvpn')

# Connect to specific server
success = await vpn_manager.connect('nordvpn', 'us3045.nordvpn.com')
```

##### `disconnect() -> bool`
Disconnect from current VPN connection.

**Returns:**
- `bool`: True if disconnection successful, False otherwise

**Example:**
```python
success = await vpn_manager.disconnect()
```

##### `get_status() -> Dict[str, Any]`
Get current VPN connection status.

**Returns:**
- `Dict[str, Any]`: Connection status information

**Example:**
```python
status = vpn_manager.get_status()
print(f"Connected: {status['connected']}")
print(f"Provider: {status['provider']}")
print(f"Server: {status['server']}")
print(f"IP Address: {status['ip_address']}")
```

##### `list_providers() -> List[str]`
Get list of available VPN providers.

**Returns:**
- `List[str]`: List of provider names

**Example:**
```python
providers = vpn_manager.list_providers()
# ['nordvpn', 'expressvpn', 'surfshark', 'cyberghost', 'protonvpn']
```

## 🏢 Provider APIs

### **Base Provider Interface**

All VPN providers implement the `BaseVPNProvider` interface.

```python
from src.providers.base import BaseVPNProvider
```

#### **Abstract Methods**

##### `authenticate(username: str, password: str) -> bool`
Authenticate with the VPN provider.

##### `connect(server: str = None) -> bool`
Connect to the VPN service.

##### `disconnect() -> bool`
Disconnect from the VPN service.

##### `get_servers() -> List[Dict[str, Any]]`
Get list of available servers.

##### `get_connection_info() -> Dict[str, Any]`
Get current connection information.

### **NordVPN Provider**

```python
from src.providers.nordvpn import NordVPNProvider

provider = NordVPNProvider()
```

#### **Specific Methods**

##### `get_recommended_servers(country: str = None) -> List[Dict]`
Get recommended servers for optimal performance.

**Parameters:**
- `country` (str, optional): Country code (e.g., 'US', 'UK', 'DE')

**Example:**
```python
servers = await provider.get_recommended_servers('US')
for server in servers:
    print(f"{server['name']} - Load: {server['load']}%")
```

##### `enable_cybersec() -> bool`
Enable NordVPN's CyberSec feature.

**Example:**
```python
success = await provider.enable_cybersec()
```

### **ExpressVPN Provider**

```python
from src.providers.expressvpn import ExpressVPNProvider

provider = ExpressVPNProvider()
```

#### **Specific Methods**

##### `activate_license(activation_code: str) -> bool`
Activate ExpressVPN license with activation code.

**Parameters:**
- `activation_code` (str): License activation code

**Example:**
```python
success = await provider.activate_license("ABCD-1234-EFGH-5678")
```

##### `get_smart_locations() -> List[Dict]`
Get ExpressVPN Smart Location recommendations.

**Example:**
```python
locations = await provider.get_smart_locations()
```

### **Surfshark Provider**

```python
from src.providers.surfshark import SurfsharkProvider

provider = SurfsharkProvider()
```

#### **Specific Methods**

##### `enable_killswitch() -> bool`
Enable Surfshark's kill switch feature.

##### `enable_cleaner() -> bool`
Enable Surfshark's ad-blocking feature.

##### `enable_bypasser(apps: List[str]) -> bool`
Configure split tunneling for specific applications.

**Parameters:**
- `apps` (List[str]): List of application names to bypass VPN

**Example:**
```python
apps_to_bypass = ['spotify.exe', 'steam.exe']
success = await provider.enable_bypasser(apps_to_bypass)
```

### **CyberGhost Provider**

```python
from src.providers.cyberghost import CyberGhostProvider

provider = CyberGhostProvider()
```

#### **Specific Methods**

##### `get_streaming_servers(service: str) -> List[Dict]`
Get servers optimized for streaming services.

**Parameters:**
- `service` (str): Streaming service ('netflix', 'hulu', 'bbc_iplayer', etc.)

**Example:**
```python
netflix_servers = await provider.get_streaming_servers('netflix')
```

##### `enable_malware_blocking() -> bool`
Enable CyberGhost's malware blocking feature.

### **ProtonVPN Provider**

```python
from src.providers.protonvpn import ProtonVPNProvider

provider = ProtonVPNProvider()
```

#### **Specific Methods**

##### `enable_secure_core() -> bool`
Enable ProtonVPN's Secure Core feature.

##### `enable_netshield() -> bool`
Enable ProtonVPN's NetShield ad-blocking.

##### `connect_tor() -> bool`
Connect through Tor network (Tor over VPN).

**Example:**
```python
# Enable maximum security
await provider.enable_secure_core()
await provider.enable_netshield()
await provider.connect_tor()
```

## 🔒 Security APIs

### **InputSanitizer Class**

```python
from src.security.input_sanitizer import InputSanitizer

sanitizer = InputSanitizer()
```

#### **Methods**

##### `sanitize_username(username: str) -> str`
Sanitize username input.

**Parameters:**
- `username` (str): Raw username input

**Returns:**
- `str`: Sanitized username

**Raises:**
- `ValidationError`: If input is invalid

**Example:**
```python
try:
    clean_username = sanitizer.sanitize_username("user@domain.com")
except ValidationError as e:
    print(f"Invalid username: {e}")
```

##### `sanitize_password(password: str) -> str`
Sanitize password input.

##### `sanitize_server_name(server_name: str) -> str`
Sanitize server name input.

##### `sanitize_ip_address(ip_address: str) -> str`
Sanitize IP address input.

### **SecureCommandExecutor Class**

```python
from src.security.secure_command_executor import SecureCommandExecutor

executor = SecureCommandExecutor()
```

#### **Methods**

##### `execute_command(command: List[str], env_vars: Dict[str, str] = None) -> CompletedProcess`
Execute command securely with input validation.

**Parameters:**
- `command` (List[str]): Command and arguments
- `env_vars` (Dict[str, str], optional): Environment variables

**Returns:**
- `CompletedProcess`: Command execution result

**Example:**
```python
result = executor.execute_command(
    ['nordvpn', 'connect'],
    env_vars={'NORDVPN_USERNAME': username, 'NORDVPN_PASSWORD': password}
)
```

### **CodeSigning Class**

```python
from src.security.code_signing import CodeSigning

signer = CodeSigning()
```

#### **Methods**

##### `sign_file(file_path: str) -> bool`
Generate digital signature for a file.

##### `verify_file(file_path: str) -> bool`
Verify digital signature of a file.

##### `verify_integrity() -> Dict[str, Any]`
Verify integrity of all VPN Hub files.

**Example:**
```python
integrity_report = signer.verify_integrity()
if integrity_report['integrity_score'] < 100:
    print("File integrity compromised!")
```

## ⚙️ Configuration APIs

### **ConfigManager Class**

```python
from src.config.config_manager import ConfigManager

config_manager = ConfigManager()
```

#### **Methods**

##### `load_config() -> Dict[str, Any]`
Load current configuration.

##### `save_config(config: Dict[str, Any]) -> bool`
Save configuration to file.

##### `get_setting(key: str, default: Any = None) -> Any`
Get specific configuration setting.

**Example:**
```python
# Get kill switch setting
kill_switch_enabled = config_manager.get_setting('network.kill_switch.enabled', False)

# Update setting
config = config_manager.load_config()
config['network']['kill_switch']['enabled'] = True
config_manager.save_config(config)
```

##### `reset_to_defaults() -> bool`
Reset configuration to default values.

### **CredentialManager Class**

```python
from src.security.credential_manager import CredentialManager

cred_manager = CredentialManager()
```

#### **Methods**

##### `store_credentials(provider: str, username: str, password: str) -> bool`
Store credentials securely in system keyring.

##### `get_credentials(provider: str) -> Tuple[str, str]`
Retrieve stored credentials.

##### `delete_credentials(provider: str) -> bool`
Delete stored credentials.

**Example:**
```python
# Store credentials
cred_manager.store_credentials('nordvpn', 'user@example.com', 'secure_password')

# Retrieve credentials
username, password = cred_manager.get_credentials('nordvpn')

# Delete credentials
cred_manager.delete_credentials('nordvpn')
```

## 📊 Monitoring APIs

### **SecurityMonitor Class**

```python
from src.security.security_monitor import SecurityMonitor

monitor = SecurityMonitor()
```

#### **Methods**

##### `get_security_events(hours: int = 24) -> List[Dict[str, Any]]`
Get recent security events.

**Parameters:**
- `hours` (int): Number of hours to look back

**Returns:**
- `List[Dict[str, Any]]`: List of security events

**Example:**
```python
events = monitor.get_security_events(24)
for event in events:
    print(f"{event['timestamp']}: {event['type']} - {event['description']}")
```

##### `get_threat_level() -> str`
Get current threat level assessment.

**Returns:**
- `str`: Threat level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')

##### `is_anomaly_detected() -> bool`
Check if any anomalies are currently detected.

### **NetworkMonitor Class**

```python
from src.monitoring.network_monitor import NetworkMonitor

net_monitor = NetworkMonitor()
```

#### **Methods**

##### `check_ip_leak() -> Dict[str, Any]`
Check for IP address leaks.

**Returns:**
- `Dict[str, Any]`: Leak detection results

**Example:**
```python
leak_check = net_monitor.check_ip_leak()
if leak_check['leak_detected']:
    print(f"IP Leak detected: {leak_check['leaked_ip']}")
```

##### `check_dns_leak() -> Dict[str, Any]`
Check for DNS leaks.

##### `get_connection_speed() -> Dict[str, float]`
Measure VPN connection speed.

**Returns:**
- `Dict[str, float]`: Speed test results (download, upload, ping)

## 🛠️ Utility APIs

### **Logger Class**

```python
from src.utils.logger import get_logger

logger = get_logger(__name__)
```

#### **Methods**

##### Standard logging methods:
- `logger.debug(message)`
- `logger.info(message)`
- `logger.warning(message)`
- `logger.error(message)`
- `logger.critical(message)`

##### `log_security_event(event_type: str, description: str, severity: str = 'INFO')`
Log security-specific events.

**Example:**
```python
logger.log_security_event(
    'AUTHENTICATION_FAILURE',
    'Failed login attempt for user: suspicious_user',
    'WARNING'
)
```

### **Encryption Utilities**

```python
from src.utils.encryption import encrypt_data, decrypt_data, generate_key
```

#### **Functions**

##### `encrypt_data(data: bytes, key: bytes) -> bytes`
Encrypt data using AES-256-GCM.

##### `decrypt_data(encrypted_data: bytes, key: bytes) -> bytes`
Decrypt data using AES-256-GCM.

##### `generate_key() -> bytes`
Generate a new encryption key.

**Example:**
```python
# Generate key
key = generate_key()

# Encrypt sensitive data
encrypted = encrypt_data(b"sensitive_data", key)

# Decrypt data
decrypted = decrypt_data(encrypted, key)
```

## 🚨 Exception Classes

### **VPNHubExceptions**

```python
from src.exceptions import (
    VPNHubException,
    AuthenticationError,
    ConnectionError,
    ValidationError,
    SecurityError,
    ConfigurationError
)
```

#### **Exception Hierarchy**

```
VPNHubException
├── AuthenticationError
├── ConnectionError
├── ValidationError
├── SecurityError
└── ConfigurationError
```

#### **Usage Example**

```python
try:
    await provider.authenticate(username, password)
except AuthenticationError as e:
    logger.error(f"Authentication failed: {e}")
except ConnectionError as e:
    logger.error(f"Connection failed: {e}")
except VPNHubException as e:
    logger.error(f"General VPN Hub error: {e}")
```

## 📝 Response Formats

### **Standard API Response**

```python
{
    "success": bool,
    "data": Any,
    "error": str | None,
    "timestamp": str,
    "request_id": str
}
```

### **Connection Status Response**

```python
{
    "connected": bool,
    "provider": str | None,
    "server": str | None,
    "ip_address": str | None,
    "location": {
        "country": str,
        "city": str,
        "coordinates": {
            "lat": float,
            "lng": float
        }
    },
    "connection_time": str | None,
    "protocol": str | None,
    "encryption": str | None
}
```

### **Security Event Response**

```python
{
    "id": str,
    "timestamp": str,
    "type": str,
    "severity": str,
    "description": str,
    "source": str,
    "details": Dict[str, Any]
}
```

## 🔧 Error Codes

| Code | Description | Action |
|------|-------------|--------|
| 1001 | Authentication Failed | Check credentials |
| 1002 | Connection Timeout | Retry connection |
| 1003 | Invalid Server | Select different server |
| 2001 | Security Violation | Review security logs |
| 2002 | Certificate Error | Update certificates |
| 3001 | Configuration Error | Check config file |
| 3002 | Permission Denied | Run with admin privileges |
| 4001 | Network Error | Check internet connection |
| 4002 | DNS Resolution Failed | Check DNS settings |

## 📚 Examples

### **Complete Connection Example**

```python
import asyncio
from src.core.vpn_manager import VPNManager
from src.security.credential_manager import CredentialManager

async def connect_vpn():
    # Initialize managers
    vpn_manager = VPNManager()
    cred_manager = CredentialManager()
    
    try:
        # Store credentials securely
        cred_manager.store_credentials(
            'nordvpn', 
            'user@example.com', 
            'secure_password'
        )
        
        # Get stored credentials
        username, password = cred_manager.get_credentials('nordvpn')
        
        # Connect to VPN
        success = await vpn_manager.connect('nordvpn')
        
        if success:
            status = vpn_manager.get_status()
            print(f"Connected to {status['server']} in {status['location']['country']}")
        else:
            print("Connection failed")
            
    except Exception as e:
        print(f"Error: {e}")

# Run the example
asyncio.run(connect_vpn())
```

### **Security Monitoring Example**

```python
from src.security.security_monitor import SecurityMonitor
from src.monitoring.network_monitor import NetworkMonitor

def security_check():
    security_monitor = SecurityMonitor()
    network_monitor = NetworkMonitor()
    
    # Check threat level
    threat_level = security_monitor.get_threat_level()
    print(f"Current threat level: {threat_level}")
    
    # Check for anomalies
    if security_monitor.is_anomaly_detected():
        print("⚠️ Security anomaly detected!")
    
    # Check for leaks
    ip_leak = network_monitor.check_ip_leak()
    dns_leak = network_monitor.check_dns_leak()
    
    if ip_leak['leak_detected']:
        print(f"🚨 IP leak detected: {ip_leak['leaked_ip']}")
    
    if dns_leak['leak_detected']:
        print(f"🚨 DNS leak detected: {dns_leak['leaked_dns']}")
    
    print("✅ Security check complete")

security_check()
```

---

**API Version:** 2.0  
**Last Updated:** November 1, 2025  
**For Support:** api-support@vpnhub.local