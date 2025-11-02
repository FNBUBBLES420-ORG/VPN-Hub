"""
Configuration Manager - Secure credential and settings management - SECURITY HARDENED
Handles encrypted storage of VPN credentials and application settings with enhanced validation
"""

import os
import json
import keyring
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib
from typing import Dict, Any, Optional, List
import logging
from pathlib import Path

try:
    from ..security.input_sanitizer import InputSanitizer, SecurityException
except ImportError:
    # Handle imports when running as standalone script
    import sys
    src_dir = Path(__file__).parent.parent
    sys.path.insert(0, str(src_dir))
    from security.input_sanitizer import InputSanitizer, SecurityException

class ConfigurationManager:
    """Manages secure storage and retrieval of VPN configurations and credentials with enhanced security"""
    
    def __init__(self, config_dir: str = None):
        self.config_dir = config_dir or os.path.join(os.path.expanduser("~"), ".vpnhub")
        
        # Validate config directory path for security
        try:
            self.config_dir = InputSanitizer.sanitize_file_path(
                self.config_dir, 
                allowed_dirs=[os.path.expanduser("~")]
            )
        except SecurityException as e:
            raise SecurityException(f"Invalid config directory: {e}")
        
        self.config_file = os.path.join(self.config_dir, "config.json")
        self.providers_file = os.path.join(self.config_dir, "providers.json")
        self.settings_file = os.path.join(self.config_dir, "settings.json")
        
        # Ensure config directory exists with secure permissions
        Path(self.config_dir).mkdir(parents=True, exist_ok=True)
        
        # Set restrictive permissions on config directory (owner only)
        try:
            os.chmod(self.config_dir, 0o700)
        except OSError:
            pass  # Windows doesn't support this
        
        # Setup secure logging
        log_file = os.path.join(self.config_dir, "config.log")
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Set restrictive permissions on log file
        try:
            if os.path.exists(log_file):
                os.chmod(log_file, 0o600)
        except OSError:
            pass
        
        # Initialize encryption
        self.cipher_suite = None
        self._init_encryption()
        
        # Load configurations
        self.config = self._load_config()
        self.providers = self._load_providers()
        self.settings = self._load_settings()
    
    def _init_encryption(self):
        """Initialize encryption for sensitive data"""
        try:
            # Try to get existing key from keyring
            key = keyring.get_password("VPNHub", "encryption_key")
            
            if not key:
                # Generate new key
                key = Fernet.generate_key().decode()
                keyring.set_password("VPNHub", "encryption_key", key)
                self.logger.info("Generated new encryption key")
            
            self.cipher_suite = Fernet(key.encode())
            
        except Exception as e:
            self.logger.error(f"Error initializing encryption: {e}")
            # Fallback to file-based key storage (less secure)
            self._init_file_based_encryption()
    
    def _init_file_based_encryption(self):
        """Fallback encryption using file-based key storage"""
        try:
            key_file = os.path.join(self.config_dir, ".encryption_key")
            
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(key_file, 'wb') as f:
                    f.write(key)
                # Make key file readable only by owner
                os.chmod(key_file, 0o600)
            
            self.cipher_suite = Fernet(key)
            self.logger.warning("Using file-based encryption key storage")
            
        except Exception as e:
            self.logger.error(f"Error with file-based encryption: {e}")
            self.cipher_suite = None
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self.cipher_suite:
            return data  # Return unencrypted if encryption failed
        
        try:
            encrypted = self.cipher_suite.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            self.logger.error(f"Error encrypting data: {e}")
            return data
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.cipher_suite:
            return encrypted_data  # Return as-is if encryption failed
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            return decrypted.decode()
        except Exception as e:
            self.logger.error(f"Error decrypting data: {e}")
            return encrypted_data
    
    def _load_config(self) -> Dict[str, Any]:
        """Load main configuration file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            else:
                # Create default config
                default_config = {
                    "version": "1.0.0",
                    "first_run": True,
                    "last_updated": "",
                    "app_settings": {
                        "auto_connect_on_startup": False,
                        "minimize_to_tray": True,
                        "check_for_updates": True,
                        "theme": "dark"
                    }
                }
                self._save_config(default_config)
                return default_config
        except Exception as e:
            self.logger.error(f"Error loading config: {e}")
            return {}
    
    def _save_config(self, config: Dict[str, Any]):
        """Save main configuration file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            self.logger.info("Configuration saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving config: {e}")
    
    def _load_providers(self) -> Dict[str, Dict]:
        """Load VPN providers configuration"""
        try:
            if os.path.exists(self.providers_file):
                with open(self.providers_file, 'r') as f:
                    encrypted_providers = json.load(f)
                
                # Decrypt sensitive data
                providers = {}
                for name, provider_data in encrypted_providers.items():
                    providers[name] = provider_data.copy()
                    if 'username' in provider_data:
                        providers[name]['username'] = self._decrypt_data(provider_data['username'])
                    if 'password' in provider_data:
                        providers[name]['password'] = self._decrypt_data(provider_data['password'])
                
                return providers
            else:
                return {}
        except Exception as e:
            self.logger.error(f"Error loading providers: {e}")
            return {}
    
    def _save_providers(self, providers: Dict[str, Dict]):
        """Save VPN providers configuration with encryption"""
        try:
            # Encrypt sensitive data before saving
            encrypted_providers = {}
            for name, provider_data in providers.items():
                encrypted_providers[name] = provider_data.copy()
                if 'username' in provider_data:
                    encrypted_providers[name]['username'] = self._encrypt_data(provider_data['username'])
                if 'password' in provider_data:
                    encrypted_providers[name]['password'] = self._encrypt_data(provider_data['password'])
            
            with open(self.providers_file, 'w') as f:
                json.dump(encrypted_providers, f, indent=2)
            
            # Make file readable only by owner
            os.chmod(self.providers_file, 0o600)
            self.logger.info("Providers configuration saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving providers: {e}")
    
    def _load_settings(self) -> Dict[str, Any]:
        """Load application settings"""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    return json.load(f)
            else:
                # Create default settings
                default_settings = {
                    "security": {
                        "kill_switch_enabled": True,
                        "dns_protection_enabled": True,
                        "auto_reconnect": True,
                        "leak_protection": True
                    },
                    "connection": {
                        "preferred_protocol": "openvpn",
                        "auto_connect_best_server": False,
                        "connection_timeout": 30,
                        "retry_attempts": 3
                    },
                    "ui": {
                        "show_notifications": True,
                        "minimize_on_close": True,
                        "start_minimized": False,
                        "update_interval": 30
                    },
                    "logging": {
                        "log_level": "INFO",
                        "max_log_size_mb": 10,
                        "keep_logs_days": 30
                    }
                }
                self._save_settings(default_settings)
                return default_settings
        except Exception as e:
            self.logger.error(f"Error loading settings: {e}")
            return {}
    
    def _save_settings(self, settings: Dict[str, Any]):
        """Save application settings"""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
            self.logger.info("Settings saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving settings: {e}")
    
    # Public methods
    
    def store_provider_credentials(self, provider: str, username: str, password: str) -> bool:
        """
        Securely store provider credentials with input validation
        
        Args:
            provider: VPN provider name
            username: User's username
            password: User's password
            
        Returns:
            True if stored successfully, False otherwise
        """
        try:
            # Sanitize and validate inputs
            provider = InputSanitizer.sanitize_provider_name(provider)
            username = InputSanitizer.sanitize_username(username)
            password = InputSanitizer.sanitize_password(password)
            
            # Create obfuscated storage keys
            username_hash = InputSanitizer.hash_sensitive_data(username)
            provider_key = f"VPNHub_{provider}"
            
            # Store credentials in system keyring with obfuscated identifiers
            try:
                keyring.set_password(provider_key, f"user_{username_hash}", username)
                keyring.set_password(provider_key, f"pass_{username_hash}", password)
                
                # Store mapping in config (without actual credentials)
                if provider not in self.providers:
                    self.providers[provider] = {}
                
                self.providers[provider].update({
                    "user_hash": username_hash,
                    "stored_securely": True,
                    "last_updated": self._get_timestamp()
                })
                
                self._save_providers(self.providers)
                
                # Log successful storage (without credentials)
                self.logger.info(f"Stored credentials for {provider} provider (user: {username_hash[:8]}...)")
                return True
                
            except Exception as keyring_error:
                # Fallback to encrypted file storage if keyring fails
                self.logger.warning(f"Keyring storage failed, using encrypted file: {keyring_error}")
                return self._store_credentials_encrypted_file(provider, username, password, username_hash)
                
        except SecurityException as e:
            self.logger.error(f"Security validation failed for credential storage: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to store credentials: {e}")
            return False
    
    def _store_credentials_encrypted_file(self, provider: str, username: str, password: str, username_hash: str) -> bool:
        """Fallback encrypted file storage for credentials"""
        try:
            if not self.cipher_suite:
                self.logger.error("Encryption not available for credential storage")
                return False
            
            # Encrypt credentials
            encrypted_username = self._encrypt_data(username)
            encrypted_password = self._encrypt_data(password)
            
            # Store in providers config
            self.providers[provider].update({
                "encrypted_username": encrypted_username,
                "encrypted_password": encrypted_password,
                "user_hash": username_hash,
                "storage_method": "encrypted_file",
                "last_updated": self._get_timestamp()
            })
            
            self._save_providers(self.providers)
            return True
            
        except Exception as e:
            self.logger.error(f"Encrypted file storage failed: {e}")
            return False
    
    def retrieve_provider_credentials(self, provider: str) -> Optional[Dict[str, str]]:
        """
        Securely retrieve provider credentials
        
        Args:
            provider: VPN provider name
            
        Returns:
            Dictionary with username and password, or None if not found
        """
        try:
            provider = InputSanitizer.sanitize_provider_name(provider)
            
            if provider not in self.providers:
                return None
            
            provider_data = self.providers[provider]
            
            # Try keyring storage first
            if provider_data.get("stored_securely"):
                return self._retrieve_from_keyring(provider, provider_data)
            
            # Try encrypted file storage
            elif provider_data.get("storage_method") == "encrypted_file":
                return self._retrieve_from_encrypted_file(provider_data)
            
            return None
            
        except SecurityException as e:
            self.logger.error(f"Security validation failed for credential retrieval: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to retrieve credentials: {e}")
            return None
    
    def _retrieve_from_keyring(self, provider: str, provider_data: Dict) -> Optional[Dict[str, str]]:
        """Retrieve credentials from system keyring"""
        try:
            username_hash = provider_data.get("user_hash")
            if not username_hash:
                return None
            
            provider_key = f"VPNHub_{provider}"
            username = keyring.get_password(provider_key, f"user_{username_hash}")
            password = keyring.get_password(provider_key, f"pass_{username_hash}")
            
            if username and password:
                return {"username": username, "password": password}
            
            return None
            
        except Exception as e:
            self.logger.error(f"Keyring retrieval failed: {e}")
            return None
    
    def _retrieve_from_encrypted_file(self, provider_data: Dict) -> Optional[Dict[str, str]]:
        """Retrieve credentials from encrypted file storage"""
        try:
            if not self.cipher_suite:
                return None
            
            encrypted_username = provider_data.get("encrypted_username")
            encrypted_password = provider_data.get("encrypted_password")
            
            if not encrypted_username or not encrypted_password:
                return None
            
            username = self._decrypt_data(encrypted_username)
            password = self._decrypt_data(encrypted_password)
            
            return {"username": username, "password": password}
            
        except Exception as e:
            self.logger.error(f"Encrypted file retrieval failed: {e}")
            return None
    
    def delete_provider_credentials(self, provider: str) -> bool:
        """
        Securely delete provider credentials
        
        Args:
            provider: VPN provider name
            
        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            provider = InputSanitizer.sanitize_provider_name(provider)
            
            if provider not in self.providers:
                return True  # Already deleted
            
            provider_data = self.providers[provider]
            
            # Delete from keyring if stored there
            if provider_data.get("stored_securely"):
                self._delete_from_keyring(provider, provider_data)
            
            # Remove from providers config
            del self.providers[provider]
            self._save_providers(self.providers)
            
            self.logger.info(f"Deleted credentials for {provider} provider")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete credentials: {e}")
            return False
    
    def _delete_from_keyring(self, provider: str, provider_data: Dict):
        """Delete credentials from system keyring"""
        try:
            username_hash = provider_data.get("user_hash")
            if username_hash:
                provider_key = f"VPNHub_{provider}"
                keyring.delete_password(provider_key, f"user_{username_hash}")
                keyring.delete_password(provider_key, f"pass_{username_hash}")
        except Exception as e:
            self.logger.warning(f"Keyring deletion failed: {e}")
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for logging"""
        import datetime
        return datetime.datetime.now().isoformat()
        """Add or update a VPN provider configuration"""
        try:
            self.providers[name.lower()] = {
                "name": provider_config.get("name", name),
                "username": provider_config.get("username", ""),
                "password": provider_config.get("password", ""),
                "config": provider_config.get("config", {}),
                "enabled": provider_config.get("enabled", True),
                "last_connected": provider_config.get("last_connected", ""),
                "connection_count": provider_config.get("connection_count", 0)
            }
            
            self._save_providers(self.providers)
            self.logger.info(f"Added/updated provider: {name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding provider {name}: {e}")
            return False
    
    def remove_provider(self, name: str) -> bool:
        """Remove a VPN provider configuration"""
        try:
            if name.lower() in self.providers:
                del self.providers[name.lower()]
                self._save_providers(self.providers)
                self.logger.info(f"Removed provider: {name}")
                return True
            else:
                self.logger.warning(f"Provider not found: {name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error removing provider {name}: {e}")
            return False
    
    def get_provider(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a specific provider configuration"""
        return self.providers.get(name.lower())
    
    def get_all_providers(self) -> Dict[str, Dict[str, Any]]:
        """Get all provider configurations"""
        return self.providers.copy()
    
    def update_provider_credentials(self, name: str, username: str, password: str) -> bool:
        """Update provider credentials"""
        try:
            if name.lower() in self.providers:
                self.providers[name.lower()]["username"] = username
                self.providers[name.lower()]["password"] = password
                self._save_providers(self.providers)
                self.logger.info(f"Updated credentials for provider: {name}")
                return True
            else:
                self.logger.warning(f"Provider not found: {name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error updating credentials for {name}: {e}")
            return False
    
    def update_setting(self, category: str, key: str, value: Any) -> bool:
        """Update a specific setting"""
        try:
            if category not in self.settings:
                self.settings[category] = {}
            
            self.settings[category][key] = value
            self._save_settings(self.settings)
            self.logger.info(f"Updated setting: {category}.{key} = {value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating setting {category}.{key}: {e}")
            return False
    
    def get_setting(self, category: str, key: str, default: Any = None) -> Any:
        """Get a specific setting value"""
        return self.settings.get(category, {}).get(key, default)
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all settings"""
        return self.settings.copy()
    
    def export_config(self, export_path: str, include_credentials: bool = False) -> bool:
        """Export configuration to a file"""
        try:
            export_data = {
                "config": self.config,
                "settings": self.settings,
                "providers": {}
            }
            
            # Export providers (optionally without credentials)
            for name, provider_data in self.providers.items():
                provider_export = provider_data.copy()
                if not include_credentials:
                    provider_export.pop("username", None)
                    provider_export.pop("password", None)
                export_data["providers"][name] = provider_export
            
            with open(export_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Configuration exported to: {export_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting configuration: {e}")
            return False
    
    def import_config(self, import_path: str, merge: bool = True) -> bool:
        """Import configuration from a file"""
        try:
            with open(import_path, 'r') as f:
                import_data = json.load(f)
            
            if merge:
                # Merge with existing configuration
                self.config.update(import_data.get("config", {}))
                self.settings.update(import_data.get("settings", {}))
                self.providers.update(import_data.get("providers", {}))
            else:
                # Replace existing configuration
                self.config = import_data.get("config", {})
                self.settings = import_data.get("settings", {})
                self.providers = import_data.get("providers", {})
            
            # Save imported configuration
            self._save_config(self.config)
            self._save_settings(self.settings)
            self._save_providers(self.providers)
            
            self.logger.info(f"Configuration imported from: {import_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error importing configuration: {e}")
            return False
    
    def backup_config(self, backup_path: str = None) -> str:
        """Create a backup of current configuration"""
        try:
            if not backup_path:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = os.path.join(self.config_dir, f"backup_{timestamp}.json")
            
            success = self.export_config(backup_path, include_credentials=True)
            if success:
                self.logger.info(f"Configuration backed up to: {backup_path}")
                return backup_path
            else:
                return ""
                
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            return ""
    
    def restore_config(self, backup_path: str) -> bool:
        """Restore configuration from a backup"""
        try:
            success = self.import_config(backup_path, merge=False)
            if success:
                self.logger.info(f"Configuration restored from: {backup_path}")
            return success
            
        except Exception as e:
            self.logger.error(f"Error restoring configuration: {e}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """Reset all configuration to defaults"""
        try:
            # Remove existing files
            for file_path in [self.config_file, self.providers_file, self.settings_file]:
                if os.path.exists(file_path):
                    os.remove(file_path)
            
            # Reload default configurations
            self.config = self._load_config()
            self.providers = self._load_providers()
            self.settings = self._load_settings()
            
            self.logger.info("Configuration reset to defaults")
            return True
            
        except Exception as e:
            self.logger.error(f"Error resetting configuration: {e}")
            return False
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get a summary of current configuration"""
        return {
            "providers_count": len(self.providers),
            "enabled_providers": len([p for p in self.providers.values() if p.get("enabled", True)]),
            "config_dir": self.config_dir,
            "encryption_available": self.cipher_suite is not None,
            "total_connections": sum(p.get("connection_count", 0) for p in self.providers.values()),
            "settings_categories": list(self.settings.keys())
        }