"""
Secure Command Executor - Prevents Command Injection Attacks
Safely executes VPN commands with credential protection and validation
"""

import asyncio
import os
import shlex
import tempfile
import subprocess
import logging
from typing import List, Optional, Dict, Tuple, Any
from pathlib import Path

try:
    from .input_sanitizer import InputSanitizer, SecurityException
except ImportError:
    # Handle imports when running as standalone script
    import sys
    src_dir = Path(__file__).parent.parent
    sys.path.insert(0, str(src_dir))
    from security.input_sanitizer import InputSanitizer, SecurityException

class SecureCommandExecutor:
    """Secure command execution for VPN operations"""
    
    # Whitelist of allowed VPN commands and their subcommands
    ALLOWED_VPN_COMMANDS = {
        'nordvpn': {
            'allowed_subcommands': ['login', 'connect', 'disconnect', 'status', 'countries', 'cities', 'groups', 'logout'],
            'credential_method': 'cli_args',  # Uses command line arguments
            'timeout': 30
        },
        'expressvpn': {
            'allowed_subcommands': ['connect', 'disconnect', 'list', 'status', 'preferences', 'activate'],
            'credential_method': 'stdin',  # Uses stdin for credentials
            'timeout': 30
        },
        'surfshark-vpn': {
            'allowed_subcommands': ['account', 'connect', 'disconnect', 'status', 'location'],
            'credential_method': 'stdin',  # Uses stdin for credentials
            'timeout': 30
        },
        'cyberghost-vpn': {
            'allowed_subcommands': ['connect', 'disconnect', 'status', 'list'],
            'credential_method': 'config',  # Uses config file
            'timeout': 30
        },
        'protonvpn': {
            'allowed_subcommands': ['connect', 'disconnect', 'status', 'list', 'login', 'logout'],
            'credential_method': 'cli_args',
            'timeout': 30
        }
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    async def execute_vpn_command(self, 
                                  command: List[str],
                                  credentials: Optional[Dict[str, str]] = None,
                                  working_dir: Optional[str] = None,
                                  timeout: Optional[int] = None) -> Tuple[int, str, str]:
        """
        Securely execute VPN commands with comprehensive security validation
        
        Args:
            command: List of command arguments (e.g., ['nordvpn', 'connect', 'server'])
            credentials: Optional dictionary with 'username' and 'password'
            working_dir: Optional working directory
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (return_code, stdout, stderr)
            
        Raises:
            SecurityException: If command is not allowed or contains malicious content
        """
        try:
            # Validate command structure
            if not command or not isinstance(command, list):
                raise SecurityException("Invalid command structure")
            
            if not all(isinstance(arg, str) for arg in command):
                raise SecurityException("All command arguments must be strings")
            
            # Get base command
            base_command = command[0]
            
            # Validate against whitelist
            if base_command not in self.ALLOWED_VPN_COMMANDS:
                raise SecurityException(f"Command '{base_command}' is not allowed")
            
            command_config = self.ALLOWED_VPN_COMMANDS[base_command]
            
            # Validate subcommands
            if len(command) > 1:
                subcommand = command[1]
                if subcommand not in command_config['allowed_subcommands']:
                    raise SecurityException(f"Subcommand '{subcommand}' not allowed for '{base_command}'")
            
            # Sanitize all command arguments
            sanitized_command = []
            for arg in command:
                # Check for shell injection patterns
                for char in InputSanitizer.SHELL_INJECTION_CHARS:
                    if char in arg:
                        raise SecurityException(f"Command argument contains prohibited character: '{char}'")
                sanitized_command.append(arg)
            
            # Set timeout
            cmd_timeout = timeout or command_config['timeout']
            
            # Prepare execution environment
            env = self._prepare_secure_environment()
            
            # Handle credentials securely based on command type
            stdin_input = None
            if credentials:
                stdin_input = await self._prepare_credentials(base_command, credentials, sanitized_command)
            
            # Validate working directory if provided
            if working_dir:
                working_dir = InputSanitizer.sanitize_file_path(working_dir)
            
            self.logger.info(f"Executing secure command: {base_command} {command[1] if len(command) > 1 else ''}")
            
            # Execute command securely
            return await self._execute_subprocess(
                sanitized_command,
                stdin_input=stdin_input,
                env=env,
                cwd=working_dir,
                timeout=cmd_timeout
            )
            
        except SecurityException:
            raise
        except asyncio.TimeoutError:
            self.logger.error(f"Command timed out after {cmd_timeout} seconds")
            raise SecurityException(f"Command timed out after {cmd_timeout} seconds")
        except Exception as e:
            self.logger.error(f"Secure command execution failed: {e}")
            raise SecurityException(f"Command execution failed: {str(e)}")
    
    def _prepare_secure_environment(self) -> Dict[str, str]:
        """Prepare a secure environment for command execution"""
        # Start with minimal environment
        secure_env = {
            'PATH': os.environ.get('PATH', ''),
            'HOME': os.environ.get('HOME', ''),
            'USER': os.environ.get('USER', ''),
            'USERPROFILE': os.environ.get('USERPROFILE', ''),
            'APPDATA': os.environ.get('APPDATA', ''),
            'LOCALAPPDATA': os.environ.get('LOCALAPPDATA', ''),
            'TEMP': os.environ.get('TEMP', ''),
            'TMP': os.environ.get('TMP', ''),
        }
        
        # Remove None values
        secure_env = {k: v for k, v in secure_env.items() if v is not None}
        
        # Add security markers
        secure_env['VPN_HUB_SECURE'] = '1'
        
        return secure_env
    
    async def _prepare_credentials(self, 
                                   command: str, 
                                   credentials: Dict[str, str],
                                   command_args: List[str]) -> Optional[bytes]:
        """
        Prepare credentials securely based on command type
        
        Args:
            command: Base command name
            credentials: Username and password
            command_args: Command arguments list
            
        Returns:
            stdin input bytes if needed, None otherwise
        """
        if not credentials:
            return None
        
        # Sanitize credentials
        try:
            username = InputSanitizer.sanitize_username(credentials.get('username', ''))
            password = InputSanitizer.sanitize_password(credentials.get('password', ''))
        except SecurityException as e:
            raise SecurityException(f"Invalid credentials: {e}")
        
        command_config = self.ALLOWED_VPN_COMMANDS[command]
        credential_method = command_config['credential_method']
        
        if credential_method == 'stdin':
            # Prepare stdin input for commands that read from stdin
            stdin_data = f"{username}\n{password}\n"
            return stdin_data.encode('utf-8')
        
        elif credential_method == 'cli_args':
            # For commands that use CLI arguments, we need to modify the command
            # This is handled in the calling function by checking the method
            # We don't return stdin data but may modify environment
            pass
        
        elif credential_method == 'config':
            # For commands that use config files, create temporary secure config
            return await self._create_secure_config_file(username, password)
        
        return None
    
    async def _create_secure_config_file(self, username: str, password: str) -> None:
        """Create a temporary secure configuration file"""
        try:
            # Create temporary file with restricted permissions
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as temp_file:
                # Write secure config format
                config_content = f"""
[credentials]
username={username}
password={password}
"""
                temp_file.write(config_content)
                temp_file_path = temp_file.name
            
            # Set restrictive permissions (owner read/write only)
            os.chmod(temp_file_path, 0o600)
            
            # Store path for cleanup
            self._temp_config_file = temp_file_path
            
        except Exception as e:
            raise SecurityException(f"Failed to create secure config file: {e}")
    
    async def _execute_subprocess(self,
                                  command: List[str],
                                  stdin_input: Optional[bytes] = None,
                                  env: Optional[Dict[str, str]] = None,
                                  cwd: Optional[str] = None,
                                  timeout: int = 30) -> Tuple[int, str, str]:
        """
        Execute subprocess with security controls
        
        Args:
            command: Sanitized command arguments
            stdin_input: Input data for stdin
            env: Environment variables
            cwd: Working directory
            timeout: Execution timeout
            
        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            # Create subprocess with security controls
            process = await asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE if stdin_input else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                cwd=cwd,
                # Additional security: prevent shell expansion
                shell=False
            )
            
            # Communicate with timeout
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=stdin_input),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                # Kill process if timeout exceeded
                process.kill()
                await process.wait()
                raise SecurityException(f"Command timed out after {timeout} seconds")
            
            # Decode output safely
            try:
                stdout_str = stdout.decode('utf-8', errors='replace') if stdout else ''
                stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ''
            except UnicodeDecodeError:
                stdout_str = str(stdout) if stdout else ''
                stderr_str = str(stderr) if stderr else ''
            
            # Clean up temporary files
            await self._cleanup_temp_files()
            
            return process.returncode, stdout_str, stderr_str
            
        except Exception as e:
            # Ensure cleanup on error
            await self._cleanup_temp_files()
            raise SecurityException(f"Subprocess execution failed: {str(e)}")
    
    async def _cleanup_temp_files(self):
        """Clean up any temporary files created during execution"""
        if hasattr(self, '_temp_config_file'):
            try:
                os.unlink(self._temp_config_file)
                delattr(self, '_temp_config_file')
            except (OSError, AttributeError):
                pass
    
    async def execute_vpn_auth(self, 
                               provider: str, 
                               username: str, 
                               password: str) -> Tuple[bool, str]:
        """
        Securely execute VPN authentication
        
        Args:
            provider: VPN provider name
            username: User's username
            password: User's password
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Sanitize inputs
            provider = InputSanitizer.sanitize_provider_name(provider)
            username = InputSanitizer.sanitize_username(username)
            password = InputSanitizer.sanitize_password(password)
            
            # Prepare authentication command based on provider
            if provider == 'nordvpn':
                command = ['nordvpn', 'login', '--username', username, '--password', password]
                return_code, stdout, stderr = await self.execute_vpn_command(command)
                
            elif provider == 'expressvpn':
                command = ['expressvpn', 'activate']
                credentials = {'username': username, 'password': password}
                return_code, stdout, stderr = await self.execute_vpn_command(command, credentials)
                
            elif provider == 'surfshark-vpn':
                command = ['surfshark-vpn', 'account', 'login']
                credentials = {'username': username, 'password': password}
                return_code, stdout, stderr = await self.execute_vpn_command(command, credentials)
                
            else:
                raise SecurityException(f"Unsupported provider: {provider}")
            
            # Evaluate authentication result
            success = return_code == 0
            message = stdout if success else stderr
            
            # Log authentication attempt (without credentials)
            user_hash = InputSanitizer.hash_sensitive_data(username)
            self.logger.info(f"Authentication attempt for {provider} user {user_hash}: {'success' if success else 'failed'}")
            
            return success, message
            
        except SecurityException:
            raise
        except Exception as e:
            self.logger.error(f"VPN authentication error: {e}")
            return False, f"Authentication failed: {str(e)}"
    
    async def execute_vpn_connect(self, 
                                  provider: str, 
                                  server: str, 
                                  protocol: Optional[str] = None) -> Tuple[bool, str]:
        """
        Securely execute VPN connection
        
        Args:
            provider: VPN provider name
            server: Server name/ID to connect to
            protocol: Optional protocol specification
            
        Returns:
            Tuple of (success, message)
        """
        try:
            # Sanitize inputs
            provider = InputSanitizer.sanitize_provider_name(provider)
            server = InputSanitizer.sanitize_server_name(server)
            
            # Build command based on provider
            if provider == 'nordvpn':
                command = ['nordvpn', 'connect', server]
                if protocol:
                    command.extend(['--protocol', protocol])
                    
            elif provider == 'expressvpn':
                command = ['expressvpn', 'connect', server]
                
            elif provider == 'surfshark-vpn':
                command = ['surfshark-vpn', 'connect', server]
                
            else:
                raise SecurityException(f"Unsupported provider: {provider}")
            
            return_code, stdout, stderr = await self.execute_vpn_command(command)
            
            success = return_code == 0
            message = stdout if success else stderr
            
            self.logger.info(f"Connection attempt to {provider}:{server}: {'success' if success else 'failed'}")
            
            return success, message
            
        except SecurityException:
            raise
        except Exception as e:
            self.logger.error(f"VPN connection error: {e}")
            return False, f"Connection failed: {str(e)}"
    
    async def execute_vpn_disconnect(self, provider: str) -> Tuple[bool, str]:
        """
        Securely execute VPN disconnection
        
        Args:
            provider: VPN provider name
            
        Returns:
            Tuple of (success, message)
        """
        try:
            provider = InputSanitizer.sanitize_provider_name(provider)
            
            # Build disconnect command
            if provider in ['nordvpn', 'expressvpn']:
                command = [provider, 'disconnect']
            elif provider == 'surfshark-vpn':
                command = ['surfshark-vpn', 'disconnect']
            else:
                raise SecurityException(f"Unsupported provider: {provider}")
            
            return_code, stdout, stderr = await self.execute_vpn_command(command)
            
            success = return_code == 0
            message = stdout if success else stderr
            
            self.logger.info(f"Disconnection from {provider}: {'success' if success else 'failed'}")
            
            return success, message
            
        except SecurityException:
            raise
        except Exception as e:
            self.logger.error(f"VPN disconnection error: {e}")
            return False, f"Disconnection failed: {str(e)}"