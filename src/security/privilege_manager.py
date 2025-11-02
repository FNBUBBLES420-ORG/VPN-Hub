"""
Privilege Management Module

This module provides:
1. Minimal privilege execution
2. User/admin separation
3. UAC prompts for sensitive operations
4. Privilege escalation controls
"""

import os
import sys
import subprocess
import ctypes
from ctypes import wintypes
import tempfile
import json
import logging
from typing import Dict, List, Optional, Union, Tuple, Callable
from pathlib import Path
from enum import Enum
import time

from .input_sanitizer import SecurityException, InputSanitizer

class PrivilegeLevel(Enum):
    """Privilege levels for operations"""
    USER = "user"
    ELEVATED = "elevated" 
    ADMIN = "admin"
    SYSTEM = "system"

class PrivilegeManager:
    """Manages privilege levels and UAC prompts for secure operations"""
    
    def __init__(self):
        """Initialize privilege manager"""
        self.logger = logging.getLogger(__name__)
        self.current_privilege_level = self._detect_current_privileges()
        
        # Operations requiring elevated privileges
        self.elevated_operations = {
            'network_config': PrivilegeLevel.ELEVATED,
            'service_management': PrivilegeLevel.ADMIN,
            'system_config': PrivilegeLevel.ADMIN,
            'firewall_config': PrivilegeLevel.ELEVATED,
            'route_management': PrivilegeLevel.ELEVATED,
            'driver_installation': PrivilegeLevel.ADMIN,
            'registry_modification': PrivilegeLevel.ADMIN
        }
        
        # Track privilege escalation attempts
        self.escalation_attempts = []
        self.max_escalation_attempts = 3
        self.escalation_cooldown = 300  # 5 minutes
        
    def _detect_current_privileges(self) -> PrivilegeLevel:
        """Detect current process privilege level"""
        try:
            if sys.platform == "win32":
                # Windows privilege detection
                if self._is_admin_windows():
                    return PrivilegeLevel.ADMIN
                elif self._is_elevated_windows():
                    return PrivilegeLevel.ELEVATED
                else:
                    return PrivilegeLevel.USER
            else:
                # Unix-like system privilege detection
                if os.geteuid() == 0:
                    return PrivilegeLevel.ADMIN
                else:
                    return PrivilegeLevel.USER
                    
        except Exception as e:
            self.logger.error(f"Failed to detect privileges: {e}")
            return PrivilegeLevel.USER
            
    def _is_admin_windows(self) -> bool:
        """Check if running as Windows administrator"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
            
    def _is_elevated_windows(self) -> bool:
        """Check if Windows process has elevated privileges"""
        try:
            # Check if process has elevated token
            hToken = wintypes.HANDLE()
            hProcess = ctypes.windll.kernel32.GetCurrentProcess()
            
            if ctypes.windll.advapi32.OpenProcessToken(hProcess, 0x0008, ctypes.byref(hToken)):
                elevation = wintypes.DWORD()
                size = wintypes.DWORD()
                
                # TOKEN_ELEVATION = 20
                if ctypes.windll.advapi32.GetTokenInformation(
                    hToken, 20, ctypes.byref(elevation), 
                    ctypes.sizeof(elevation), ctypes.byref(size)
                ):
                    ctypes.windll.kernel32.CloseHandle(hToken)
                    return elevation.value != 0
                    
                ctypes.windll.kernel32.CloseHandle(hToken)
            return False
        except:
            return False
            
    def get_current_privilege_level(self) -> PrivilegeLevel:
        """Get current privilege level"""
        return self.current_privilege_level
        
    def requires_elevation(self, operation: str) -> bool:
        """Check if operation requires privilege elevation"""
        required_level = self.elevated_operations.get(operation, PrivilegeLevel.USER)
        current_level_value = list(PrivilegeLevel).index(self.current_privilege_level)
        required_level_value = list(PrivilegeLevel).index(required_level)
        
        return required_level_value > current_level_value
        
    def can_escalate_privileges(self) -> bool:
        """Check if privilege escalation is allowed"""
        try:
            # Check escalation attempt limits
            current_time = time.time()
            recent_attempts = [
                attempt for attempt in self.escalation_attempts
                if current_time - attempt['timestamp'] < self.escalation_cooldown
            ]
            
            if len(recent_attempts) >= self.max_escalation_attempts:
                self.logger.warning("Privilege escalation blocked - too many recent attempts")
                return False
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking escalation capability: {e}")
            return False
            
    def prompt_for_elevation(self, operation: str, reason: str) -> bool:
        """Prompt user for privilege elevation"""
        try:
            if not self.can_escalate_privileges():
                return False
                
            # Record escalation attempt
            self.escalation_attempts.append({
                'operation': operation,
                'reason': reason,
                'timestamp': time.time()
            })
            
            if sys.platform == "win32":
                return self._prompt_uac_windows(operation, reason)
            else:
                return self._prompt_sudo_unix(operation, reason)
                
        except Exception as e:
            self.logger.error(f"Elevation prompt failed: {e}")
            return False
            
    def _prompt_uac_windows(self, operation: str, reason: str) -> bool:
        """Prompt for Windows UAC elevation"""
        try:
            # Create elevated command script
            script_content = f'''
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Verify elevation
import ctypes
if not ctypes.windll.shell32.IsUserAnAdmin():
    print("ERROR: Elevation failed")
    sys.exit(1)

print("SUCCESS: Elevated privileges granted")
sys.exit(0)
'''
            
            # Write temporary script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(script_content)
                script_path = f.name
                
            try:
                # Run with UAC prompt
                result = subprocess.run([
                    'powershell', 
                    '-Command',
                    f'Start-Process python -ArgumentList "{script_path}" -Verb RunAs -Wait'
                ], capture_output=True, text=True, timeout=60)
                
                success = result.returncode == 0
                if success:
                    self.logger.info(f"UAC elevation granted for {operation}")
                else:
                    self.logger.warning(f"UAC elevation denied for {operation}")
                    
                return success
                
            finally:
                # Clean up temporary script
                try:
                    os.unlink(script_path)
                except:
                    pass
                    
        except Exception as e:
            self.logger.error(f"UAC prompt failed: {e}")
            return False
            
    def _prompt_sudo_unix(self, operation: str, reason: str) -> bool:
        """Prompt for Unix sudo elevation"""
        try:
            # Use sudo to check privileges
            result = subprocess.run([
                'sudo', '-n', 'true'
            ], capture_output=True, timeout=5)
            
            if result.returncode == 0:
                self.logger.info(f"Sudo elevation available for {operation}")
                return True
            else:
                # Prompt for password
                result = subprocess.run([
                    'sudo', '-p', 
                    f'VPN Hub requires elevated privileges for {operation}.\nReason: {reason}\nPassword: ',
                    'true'
                ], timeout=60)
                
                success = result.returncode == 0
                if success:
                    self.logger.info(f"Sudo elevation granted for {operation}")
                else:
                    self.logger.warning(f"Sudo elevation denied for {operation}")
                    
                return success
                
        except Exception as e:
            self.logger.error(f"Sudo prompt failed: {e}")
            return False
            
    def execute_with_privileges(self, 
                               operation: str,
                               command: List[str],
                               reason: str,
                               working_dir: Optional[str] = None) -> Tuple[int, str, str]:
        """Execute command with appropriate privileges"""
        try:
            # Validate operation
            if operation not in self.elevated_operations:
                raise SecurityException(f"Unknown operation: {operation}")
                
            # Check if elevation is required
            if not self.requires_elevation(operation):
                # Execute with current privileges
                return self._execute_command(command, working_dir)
                
            # Check if elevation is possible and prompt user
            if not self.prompt_for_elevation(operation, reason):
                raise SecurityException(f"Privilege elevation denied for {operation}")
                
            # Execute with elevated privileges
            return self._execute_elevated_command(command, working_dir)
            
        except Exception as e:
            self.logger.error(f"Privileged execution failed: {e}")
            raise SecurityException(f"Privileged execution failed: {e}")
            
    def _execute_command(self, 
                        command: List[str], 
                        working_dir: Optional[str] = None) -> Tuple[int, str, str]:
        """Execute command with current privileges"""
        try:
            # Validate command
            for arg in command:
                InputSanitizer.sanitize_command_argument(arg)
                
            result = subprocess.run(
                command,
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode, result.stdout, result.stderr
            
        except Exception as e:
            raise SecurityException(f"Command execution failed: {e}")
            
    def _execute_elevated_command(self, 
                                 command: List[str], 
                                 working_dir: Optional[str] = None) -> Tuple[int, str, str]:
        """Execute command with elevated privileges"""
        try:
            if sys.platform == "win32":
                return self._execute_elevated_windows(command, working_dir)
            else:
                return self._execute_elevated_unix(command, working_dir)
                
        except Exception as e:
            raise SecurityException(f"Elevated execution failed: {e}")
            
    def _execute_elevated_windows(self, 
                                 command: List[str], 
                                 working_dir: Optional[str] = None) -> Tuple[int, str, str]:
        """Execute command with Windows elevation"""
        try:
            # Create PowerShell script for elevated execution
            ps_command = f'''
$process = Start-Process -FilePath "{command[0]}" -ArgumentList @({",".join(f'"{arg}"' for arg in command[1:])}) -Wait -PassThru -NoNewWindow
if ($process.ExitCode -eq $null) {{
    $process.ExitCode = 0
}}
exit $process.ExitCode
'''
            
            # Execute with elevation
            result = subprocess.run([
                'powershell',
                '-Command',
                f'Start-Process powershell -ArgumentList "-Command", "{ps_command}" -Verb RunAs -Wait'
            ], cwd=working_dir, capture_output=True, text=True, timeout=60)
            
            return result.returncode, result.stdout, result.stderr
            
        except Exception as e:
            raise SecurityException(f"Windows elevated execution failed: {e}")
            
    def _execute_elevated_unix(self, 
                              command: List[str], 
                              working_dir: Optional[str] = None) -> Tuple[int, str, str]:
        """Execute command with Unix sudo"""
        try:
            # Prepend sudo to command
            elevated_command = ['sudo'] + command
            
            result = subprocess.run(
                elevated_command,
                cwd=working_dir,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return result.returncode, result.stdout, result.stderr
            
        except Exception as e:
            raise SecurityException(f"Unix elevated execution failed: {e}")
            
    def configure_network_interface(self, interface_name: str, dns_servers: List[str]) -> bool:
        """Configure network interface with elevated privileges"""
        try:
            # Validate inputs
            interface_name = InputSanitizer.sanitize_server_name(interface_name)
            for dns in dns_servers:
                InputSanitizer.sanitize_ip_address(dns)
                
            if sys.platform == "win32":
                command = [
                    'netsh', 'interface', 'ipv4', 'set', 'dnsservers',
                    interface_name, 'static', dns_servers[0]
                ]
            else:
                # Linux/macOS
                command = [
                    'resolvectl', 'dns', interface_name
                ] + dns_servers
                
            return_code, stdout, stderr = self.execute_with_privileges(
                'network_config',
                command,
                f'Configure DNS servers for interface {interface_name}'
            )
            
            success = return_code == 0
            if success:
                self.logger.info(f"Successfully configured network interface {interface_name}")
            else:
                self.logger.error(f"Network configuration failed: {stderr}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Network interface configuration failed: {e}")
            return False
            
    def manage_windows_service(self, service_name: str, action: str) -> bool:
        """Manage Windows service with elevated privileges"""
        try:
            if sys.platform != "win32":
                raise SecurityException("Windows service management only available on Windows")
                
            # Validate inputs
            service_name = InputSanitizer.sanitize_server_name(service_name)
            if action not in ['start', 'stop', 'restart', 'status']:
                raise SecurityException(f"Invalid service action: {action}")
                
            command = ['sc', action, service_name]
            
            return_code, stdout, stderr = self.execute_with_privileges(
                'service_management',
                command,
                f'{action.title()} Windows service {service_name}'
            )
            
            success = return_code == 0
            if success:
                self.logger.info(f"Successfully {action}ed service {service_name}")
            else:
                self.logger.error(f"Service management failed: {stderr}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Service management failed: {e}")
            return False
            
    def configure_firewall_rule(self, rule_name: str, port: int, protocol: str = 'tcp') -> bool:
        """Configure firewall rule with elevated privileges"""
        try:
            # Validate inputs
            rule_name = InputSanitizer.sanitize_server_name(rule_name)
            InputSanitizer.sanitize_port_number(port)
            
            if protocol not in ['tcp', 'udp']:
                raise SecurityException(f"Invalid protocol: {protocol}")
                
            if sys.platform == "win32":
                command = [
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    f'name={rule_name}',
                    'dir=in',
                    'action=allow',
                    f'protocol={protocol}',
                    f'localport={port}'
                ]
            else:
                # Linux iptables
                command = [
                    'iptables', '-A', 'INPUT', '-p', protocol,
                    '--dport', str(port), '-j', 'ACCEPT'
                ]
                
            return_code, stdout, stderr = self.execute_with_privileges(
                'firewall_config',
                command,
                f'Configure firewall rule for {rule_name} ({protocol}:{port})'
            )
            
            success = return_code == 0
            if success:
                self.logger.info(f"Successfully configured firewall rule {rule_name}")
            else:
                self.logger.error(f"Firewall configuration failed: {stderr}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Firewall configuration failed: {e}")
            return False
            
    def create_privilege_drop_context(self, target_user: Optional[str] = None):
        """Create context manager for dropping privileges temporarily"""
        return PrivilegeDropContext(self, target_user)
        
    def get_privilege_report(self) -> Dict[str, any]:
        """Get comprehensive privilege status report"""
        try:
            report = {
                'current_privilege_level': self.current_privilege_level.value,
                'is_elevated': self.current_privilege_level in [PrivilegeLevel.ELEVATED, PrivilegeLevel.ADMIN],
                'escalation_attempts_count': len(self.escalation_attempts),
                'recent_escalations': [
                    {
                        'operation': attempt['operation'],
                        'timestamp': attempt['timestamp'],
                        'reason': attempt['reason']
                    }
                    for attempt in self.escalation_attempts[-5:]  # Last 5 attempts
                ],
                'can_escalate': self.can_escalate_privileges(),
                'platform': sys.platform,
                'process_id': os.getpid()
            }
            
            if sys.platform == "win32":
                report['windows_admin'] = self._is_admin_windows()
                report['windows_elevated'] = self._is_elevated_windows()
            else:
                report['effective_uid'] = os.geteuid()
                report['real_uid'] = os.getuid()
                
            return report
            
        except Exception as e:
            self.logger.error(f"Privilege report generation failed: {e}")
            return {'error': str(e)}

class PrivilegeDropContext:
    """Context manager for temporarily dropping privileges"""
    
    def __init__(self, privilege_manager: PrivilegeManager, target_user: Optional[str] = None):
        self.privilege_manager = privilege_manager
        self.target_user = target_user
        self.original_uid = None
        self.original_gid = None
        
    def __enter__(self):
        """Drop privileges on context entry"""
        try:
            if sys.platform != "win32" and os.geteuid() == 0:
                # Save original IDs
                self.original_uid = os.geteuid()
                self.original_gid = os.getegid()
                
                # Drop to specified user or nobody
                if self.target_user:
                    import pwd
                    pw_record = pwd.getpwnam(self.target_user)
                    target_uid = pw_record.pw_uid
                    target_gid = pw_record.pw_gid
                else:
                    # Drop to nobody
                    target_uid = 65534  # nobody UID
                    target_gid = 65534  # nobody GID
                    
                os.setegid(target_gid)
                os.seteuid(target_uid)
                
                self.privilege_manager.logger.info(f"Dropped privileges to UID {target_uid}")
                
        except Exception as e:
            self.privilege_manager.logger.error(f"Failed to drop privileges: {e}")
            
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore privileges on context exit"""
        try:
            if self.original_uid is not None and self.original_gid is not None:
                os.seteuid(self.original_uid)
                os.setegid(self.original_gid)
                self.privilege_manager.logger.info("Restored original privileges")
                
        except Exception as e:
            self.privilege_manager.logger.error(f"Failed to restore privileges: {e}")

# Global instance
_privilege_manager = None

def get_privilege_manager() -> PrivilegeManager:
    """Get global privilege manager instance"""
    global _privilege_manager
    if _privilege_manager is None:
        _privilege_manager = PrivilegeManager()
    return _privilege_manager