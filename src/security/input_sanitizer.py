"""
Input Sanitization Module - Critical Security Component
Prevents command injection and validates all user inputs
"""

import re
import shlex
import hashlib
from typing import List, Optional, Dict, Any
import logging

class SecurityException(Exception):
    """Custom exception for security violations"""
    pass

class InputSanitizer:
    """Comprehensive input sanitization for VPN Hub application"""
    
    # Maximum allowed input lengths
    MAX_USERNAME_LENGTH = 100
    MAX_PASSWORD_LENGTH = 200
    MAX_SERVER_NAME_LENGTH = 50
    MAX_PROVIDER_NAME_LENGTH = 30
    
    # Dangerous characters and patterns
    SHELL_INJECTION_CHARS = ['`', '$', '|', '&', ';', '<', '>', '\n', '\r', '\t', '\\']
    COMMAND_INJECTION_PATTERNS = [
        r'[;&|`$]',      # Shell metacharacters
        r'\$\(',         # Command substitution $(...)
        r'`[^`]*`',      # Backtick execution (must have content)
        r'>\s*[/\\]',    # File redirection to system paths
        r'<\s*[/\\]',    # File input from system paths
        r'\|\s*\w+\s',   # Pipe to commands (with space after)
        r'&&|\|\|',      # Command chaining (&& or ||)
        r'\.\./.*',      # Path traversal
        r'\$\{.*\}',     # Variable expansion ${...}
    ]
    
    @staticmethod
    def sanitize_username(username: str) -> str:
        """
        Sanitize username input to prevent command injection
        
        Args:
            username: Raw username input
            
        Returns:
            Sanitized username
            
        Raises:
            SecurityException: If username contains malicious content
        """
        if not username:
            raise SecurityException("Username cannot be empty")
        
        # Strip whitespace
        username = username.strip()
        
        # Check length
        if len(username) > InputSanitizer.MAX_USERNAME_LENGTH:
            raise SecurityException(f"Username too long (max {InputSanitizer.MAX_USERNAME_LENGTH} characters)")
        
        if len(username) < 1:
            raise SecurityException("Username too short")
        
        # Check for dangerous characters
        for char in InputSanitizer.SHELL_INJECTION_CHARS:
            if char in username:
                raise SecurityException(f"Username contains prohibited character: '{char}'")
        
        # Check for injection patterns
        for pattern in InputSanitizer.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, username, re.IGNORECASE):
                raise SecurityException("Username contains suspicious patterns")
        
        # Allow only alphanumeric, dots, underscores, hyphens, and @ symbol (for email usernames)
        if not re.match(r'^[a-zA-Z0-9._@-]+$', username):
            raise SecurityException("Username contains invalid characters (allowed: letters, numbers, ., _, @, -)")
        
        # Additional security checks
        if username.startswith('-') or username.startswith('.'):
            raise SecurityException("Username cannot start with - or .")
        
        return username
    
    @staticmethod
    def sanitize_password(password: str, gui_mode: bool = False) -> str:
        """
        Sanitize password input to prevent command injection
        
        Args:
            password: Raw password input
            gui_mode: If True, allows more characters for GUI-based authentication
            
        Returns:
            Sanitized password
            
        Raises:
            SecurityException: If password contains malicious content
        """
        if not password:
            raise SecurityException("Password cannot be empty")
        
        # Check length
        if len(password) > InputSanitizer.MAX_PASSWORD_LENGTH:
            raise SecurityException(f"Password too long (max {InputSanitizer.MAX_PASSWORD_LENGTH} characters)")
        
        if len(password) < 1:
            raise SecurityException("Password too short")
        
        # For GUI mode, be very permissive since password is handled by GUI, not CLI
        if gui_mode:
            # Only block extremely dangerous characters that could never be in a password
            dangerous_chars = ['\n', '\r', '\x00']  # Only newlines and null bytes
            for char in dangerous_chars:
                if char in password:
                    raise SecurityException(f"Password contains prohibited character")
            
            # Only check for obvious command injection - be very conservative
            if '`' in password and password.count('`') >= 2:
                # Only block if there are paired backticks (command execution)
                if re.search(r'`[^`]+`', password):
                    raise SecurityException("Password contains command execution pattern")
            
            # Check for command substitution with $( only
            if '$(' in password and ')' in password:
                if re.search(r'\$\([^)]*\)', password):
                    raise SecurityException("Password contains command substitution pattern")
        else:
            # Standard CLI mode - more restrictive
            dangerous_chars = ['`', '$', '|', '&', ';', '<', '>', '\n', '\r', '\t']
            for char in dangerous_chars:
                if char in password:
                    raise SecurityException(f"Password contains prohibited character")
            
            # Check for command injection patterns
            for pattern in InputSanitizer.COMMAND_INJECTION_PATTERNS:
                if re.search(pattern, password, re.IGNORECASE):
                    raise SecurityException("Password contains suspicious patterns")
        
        # Check for null bytes
        if '\x00' in password:
            raise SecurityException("Password contains null bytes")
        
        return password
    
    @staticmethod
    def sanitize_server_name(server_name: str) -> str:
        """
        Sanitize server name input
        
        Args:
            server_name: Raw server name input
            
        Returns:
            Sanitized server name
            
        Raises:
            SecurityException: If server name contains malicious content
        """
        if not server_name:
            raise SecurityException("Server name cannot be empty")
        
        # Strip whitespace
        server_name = server_name.strip()
        
        # Check length
        if len(server_name) > InputSanitizer.MAX_SERVER_NAME_LENGTH:
            raise SecurityException(f"Server name too long (max {InputSanitizer.MAX_SERVER_NAME_LENGTH} characters)")
        
        # Check for dangerous characters
        for char in InputSanitizer.SHELL_INJECTION_CHARS:
            if char in server_name:
                raise SecurityException(f"Server name contains prohibited character: '{char}'")
        
        # Allow alphanumeric, dots, hyphens only (valid hostname format)
        if not re.match(r'^[a-zA-Z0-9.-]+$', server_name):
            raise SecurityException("Server name contains invalid characters (allowed: letters, numbers, ., -)")
        
        # Additional hostname validation
        if server_name.startswith('-') or server_name.endswith('-'):
            raise SecurityException("Server name cannot start or end with hyphen")
        
        if '..' in server_name:
            raise SecurityException("Server name cannot contain consecutive dots")
        
        return server_name
    
    @staticmethod
    def sanitize_provider_name(provider_name: str) -> str:
        """
        Sanitize VPN provider name
        
        Args:
            provider_name: Raw provider name
            
        Returns:
            Sanitized provider name
            
        Raises:
            SecurityException: If provider name is invalid
        """
        if not provider_name:
            raise SecurityException("Provider name cannot be empty")
        
        provider_name = provider_name.strip()
        
        # Check length
        if len(provider_name) > InputSanitizer.MAX_PROVIDER_NAME_LENGTH:
            raise SecurityException(f"Provider name too long (max {InputSanitizer.MAX_PROVIDER_NAME_LENGTH} characters)")
        
        # Allow only letters, numbers, and hyphens
        if not re.match(r'^[a-zA-Z0-9-]+$', provider_name):
            raise SecurityException("Provider name contains invalid characters")
        
        return provider_name.lower()
    
    @staticmethod
    def sanitize_ip_address(ip_address: str) -> str:
        """
        Sanitize IP address input
        
        Args:
            ip_address: Raw IP address
            
        Returns:
            Sanitized IP address
            
        Raises:
            SecurityException: If IP address is invalid
        """
        if not ip_address:
            raise SecurityException("IP address cannot be empty")
        
        ip_address = ip_address.strip()
        
        # Basic IPv4 pattern check
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # Basic IPv6 pattern check (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        
        if not (re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address)):
            raise SecurityException("Invalid IP address format")
        
        # Additional IPv4 validation
        if re.match(ipv4_pattern, ip_address):
            octets = ip_address.split('.')
            for octet in octets:
                if int(octet) > 255:
                    raise SecurityException("Invalid IPv4 address: octet too large")
        
        return ip_address
    
    @staticmethod
    def sanitize_port(port: str) -> int:
        """
        Sanitize port number input
        
        Args:
            port: Raw port input
            
        Returns:
            Sanitized port number
            
        Raises:
            SecurityException: If port is invalid
        """
        if not port:
            raise SecurityException("Port cannot be empty")
        
        try:
            port_num = int(port.strip())
        except ValueError:
            raise SecurityException("Port must be a number")
        
        if port_num < 1 or port_num > 65535:
            raise SecurityException("Port must be between 1 and 65535")
        
        return port_num
    
    @staticmethod
    def sanitize_file_path(file_path: str, allowed_dirs: List[str] = None) -> str:
        """
        Sanitize file path to prevent directory traversal
        
        Args:
            file_path: Raw file path
            allowed_dirs: List of allowed base directories
            
        Returns:
            Sanitized file path
            
        Raises:
            SecurityException: If path is dangerous
        """
        if not file_path:
            raise SecurityException("File path cannot be empty")
        
        file_path = file_path.strip()
        
        # Check for path traversal attempts
        if '..' in file_path:
            raise SecurityException("Path traversal detected")
        
        # Check for absolute paths to restricted areas
        dangerous_paths = ['/etc/', '/proc/', '/sys/', 'C:\\Windows\\', 'C:\\System32\\']
        for dangerous_path in dangerous_paths:
            if file_path.lower().startswith(dangerous_path.lower()):
                raise SecurityException("Access to system directories not allowed")
        
        # If allowed directories specified, ensure path is within them
        if allowed_dirs:
            import os
            abs_path = os.path.abspath(file_path)
            allowed = False
            for allowed_dir in allowed_dirs:
                if abs_path.startswith(os.path.abspath(allowed_dir)):
                    allowed = True
                    break
            if not allowed:
                raise SecurityException("File path outside allowed directories")
        
        return file_path
    
    @staticmethod
    def validate_command_args(command_args: List[str], allowed_commands: Dict[str, List[str]]) -> List[str]:
        """
        Validate command arguments against whitelist
        
        Args:
            command_args: List of command arguments
            allowed_commands: Dictionary of allowed commands and their subcommands
            
        Returns:
            Validated command arguments
            
        Raises:
            SecurityException: If command is not allowed
        """
        if not command_args:
            raise SecurityException("Command arguments cannot be empty")
        
        base_command = command_args[0]
        
        # Check if base command is allowed
        if base_command not in allowed_commands:
            raise SecurityException(f"Command '{base_command}' is not allowed")
        
        # Check subcommands if present
        if len(command_args) > 1:
            subcommand = command_args[1]
            if subcommand not in allowed_commands[base_command]:
                raise SecurityException(f"Subcommand '{subcommand}' not allowed for '{base_command}'")
        
        # Sanitize all arguments
        sanitized_args = []
        for arg in command_args:
            # Check for shell injection in arguments
            for char in InputSanitizer.SHELL_INJECTION_CHARS:
                if char in arg:
                    raise SecurityException(f"Command argument contains prohibited character: '{char}'")
            sanitized_args.append(arg)
        
        return sanitized_args
    
    @staticmethod
    def hash_sensitive_data(data: str, salt: str = None) -> str:
        """
        Create secure hash of sensitive data for logging/storage
        
        Args:
            data: Sensitive data to hash
            salt: Optional salt for hashing
            
        Returns:
            Secure hash string
        """
        if salt is None:
            salt = "vpnhub_security_salt"
        
        hash_obj = hashlib.pbkdf2_hmac('sha256', 
                                       data.encode('utf-8'), 
                                       salt.encode('utf-8'), 
                                       100000)  # 100k iterations
        return hash_obj.hex()[:16]  # Return first 16 chars for logging
