# VPN Hub Configuration Guide

Complete configuration guide for VPN Hub enterprise-grade secure VPN manager.

## 📋 Table of Contents

- [Security Configuration](#security-configuration)
- [Provider Configuration](#provider-configuration)
- [GUI Configuration](#gui-configuration)
- [Network Configuration](#network-configuration)
- [Logging Configuration](#logging-configuration)
- [Advanced Configuration](#advanced-configuration)

## 🔒 Security Configuration

### **Core Security Settings**

#### Input Sanitization Configuration
```python
# src/config/security_config.py
SECURITY_CONFIG = {
    'input_sanitization': {
        'max_username_length': 100,
        'max_password_length': 200,
        'max_server_name_length': 255,
        'allowed_username_chars': r'[a-zA-Z0-9._@-]',
        'blocked_patterns': [
            r'[;&|`$(){}[\]\\<>]',  # Shell metacharacters
            r'\.\./',               # Directory traversal
            r'DROP\s+TABLE',        # SQL injection
            r'<script',             # XSS
        ]
    }
}
```

#### Code Signing Configuration
```python
CODE_SIGNING_CONFIG = {
    'key_size': 4096,
    'signature_algorithm': 'SHA-256',
    'key_storage_path': '~/.vpn_hub/keys/',
    'verification_on_startup': True,
    'real_time_monitoring': True
}
```

#### Network Security Configuration
```python
NETWORK_SECURITY_CONFIG = {
    'tls_version': 'TLSv1.2',
    'certificate_pinning': True,
    'dns_servers': [
        '1.1.1.1',      # Cloudflare
        '8.8.8.8',      # Google
        '9.9.9.9'       # Quad9
    ],
    'connection_timeout': 30,
    'verify_ssl': True
}
```

### **Privilege Management**
```python
PRIVILEGE_CONFIG = {
    'escalation_prompt': True,
    'escalation_timeout': 300,  # 5 minutes
    'log_escalations': True,
    'required_for': [
        'network_interface_modification',
        'route_table_changes',
        'firewall_rules'
    ]
}
```

## 🔌 Provider Configuration

### **Provider Registration**
```python
# config/providers.yaml
providers:
  nordvpn:
    enabled: true
    auth_method: "credentials"
    api_endpoint: "https://api.nordvpn.com"
    certificate_pinning: true
    protocols: ["openvpn", "wireguard"]
    
  expressvpn:
    enabled: true
    auth_method: "activation_code"
    api_endpoint: "https://api.expressvpn.com"
    certificate_pinning: true
    protocols: ["lightway", "openvpn"]
    
  surfshark:
    enabled: true
    auth_method: "credentials"
    api_endpoint: "https://api.surfshark.com"
    certificate_pinning: true
    protocols: ["wireguard", "openvpn"]
    
  cyberghost:
    enabled: true
    auth_method: "credentials"
    api_endpoint: "https://api.cyberghostvpn.com"
    protocols: ["wireguard", "openvpn"]
    
  protonvpn:
    enabled: true
    auth_method: "credentials"
    api_endpoint: "https://api.protonvpn.ch"
    protocols: ["wireguard", "openvpn"]
```

### **Credential Storage Configuration**
```python
CREDENTIAL_CONFIG = {
    'storage_backend': 'system_keyring',
    'encryption_algorithm': 'AES-256-GCM',
    'key_derivation': 'PBKDF2',
    'iterations': 100000,
    'salt_length': 32
}
```

## 🖥️ GUI Configuration

### **Appearance Settings**
```python
# config/gui_config.py
GUI_CONFIG = {
    'theme': 'dark',
    'window_size': (800, 600),
    'window_position': 'center',
    'always_on_top': False,
    'minimize_to_tray': True,
    'close_to_tray': True,
    'startup_minimized': False
}
```

### **Behavior Settings**
```python
BEHAVIOR_CONFIG = {
    'auto_connect': False,
    'remember_last_server': True,
    'connection_timeout': 30,
    'reconnect_attempts': 3,
    'kill_switch': True,
    'dns_leak_protection': True
}
```

### **System Tray Configuration**
```python
SYSTEM_TRAY_CONFIG = {
    'enabled': True,
    'show_notifications': True,
    'notification_duration': 5000,  # milliseconds
    'show_connection_status': True,
    'quick_connect_servers': 5
}
```

## 🌐 Network Configuration

### **Connection Settings**
```python
NETWORK_CONFIG = {
    'default_protocol': 'auto',
    'preferred_protocols': ['wireguard', 'openvpn'],
    'connection_timeout': 30,
    'keep_alive_interval': 60,
    'mtu_size': 1420
}
```

### **Kill Switch Configuration**
```python
KILL_SWITCH_CONFIG = {
    'enabled': True,
    'block_ipv6': True,
    'block_lan': False,
    'allow_local_network': True,
    'emergency_disconnect': True
}
```

### **DNS Configuration**
```python
DNS_CONFIG = {
    'leak_protection': True,
    'custom_dns': [],
    'fallback_dns': ['1.1.1.1', '8.8.8.8'],
    'dns_over_https': True,
    'dns_over_tls': True
}
```

## 📊 Logging Configuration

### **Log Levels and Output**
```python
LOGGING_CONFIG = {
    'level': 'INFO',
    'file_logging': True,
    'console_logging': True,
    'max_file_size': '10MB',
    'backup_count': 5,
    'log_directory': '~/.vpn_hub/logs/',
    'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
}
```

### **Security Logging**
```python
SECURITY_LOGGING_CONFIG = {
    'enabled': True,
    'log_authentication': True,
    'log_connections': True,
    'log_disconnections': True,
    'log_errors': True,
    'log_security_events': True,
    'separate_security_log': True
}
```

## ⚙️ Advanced Configuration

### **Performance Tuning**
```python
PERFORMANCE_CONFIG = {
    'connection_pool_size': 10,
    'request_timeout': 30,
    'max_retries': 3,
    'backoff_factor': 0.3,
    'thread_pool_size': 4
}
```

### **Security Monitoring**
```python
MONITORING_CONFIG = {
    'real_time_monitoring': True,
    'anomaly_detection': True,
    'brute_force_protection': True,
    'max_failed_attempts': 5,
    'lockout_duration': 300,  # 5 minutes
    'security_alerts': True
}
```

### **Update Configuration**
```python
UPDATE_CONFIG = {
    'auto_check_updates': True,
    'update_channel': 'stable',
    'check_interval': 86400,  # 24 hours
    'download_updates': False,
    'notify_updates': True
}
```

## 📁 Configuration File Locations

### **Default Paths**

#### Windows
```
Config Directory: %APPDATA%\VPNHub\
Main Config: %APPDATA%\VPNHub\config.yaml
Security Config: %APPDATA%\VPNHub\security.yaml
Logs: %APPDATA%\VPNHub\logs\
```

#### macOS
```
Config Directory: ~/Library/Application Support/VPNHub/
Main Config: ~/Library/Application Support/VPNHub/config.yaml
Security Config: ~/Library/Application Support/VPNHub/security.yaml
Logs: ~/Library/Application Support/VPNHub/logs/
```

#### Linux
```
Config Directory: ~/.config/vpnhub/
Main Config: ~/.config/vpnhub/config.yaml
Security Config: ~/.config/vpnhub/security.yaml
Logs: ~/.local/share/vpnhub/logs/
```

## 🔧 Configuration Management

### **Creating Custom Configuration**
```python
from src.config import ConfigManager

# Initialize configuration manager
config_manager = ConfigManager()

# Load default configuration
config = config_manager.load_default_config()

# Customize settings
config['security']['input_sanitization']['max_username_length'] = 150
config['gui']['theme'] = 'light'
config['network']['kill_switch']['enabled'] = True

# Save configuration
config_manager.save_config(config)
```

### **Environment Variables**
```bash
# Override configuration with environment variables
export VPN_HUB_LOG_LEVEL=DEBUG
export VPN_HUB_CONFIG_PATH=/custom/path/config.yaml
export VPN_HUB_SECURITY_MODE=strict
export VPN_HUB_GUI_THEME=dark
```

### **Command Line Arguments**
```bash
# Launch with custom configuration
python src/main.py --config /path/to/config.yaml
python src/main.py --log-level DEBUG
python src/main.py --no-gui
python src/main.py --security-mode strict
```

## 🛡️ Security Best Practices

1. **Always use encrypted credential storage**
2. **Enable certificate pinning for all providers**
3. **Use strong passwords with 2FA when available**
4. **Regularly update configuration files**
5. **Monitor security logs for anomalies**
6. **Keep configuration files with restricted permissions**
7. **Use environment variables for sensitive data**

## 🔍 Troubleshooting Configuration

### **Common Issues**

#### Configuration File Not Found
```bash
# Check file permissions
ls -la ~/.config/vpnhub/config.yaml

# Recreate default configuration
python -c "from src.config import create_default_config; create_default_config()"
```

#### Invalid Configuration Format
```bash
# Validate configuration syntax
python -c "from src.config import validate_config; validate_config('config.yaml')"
```

#### Permission Errors
```bash
# Fix configuration directory permissions
chmod 700 ~/.config/vpnhub/
chmod 600 ~/.config/vpnhub/*.yaml
```

---

**Last Updated:** November 1, 2025  
**For Support:** docs@vpnhub.local