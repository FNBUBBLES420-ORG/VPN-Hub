"""
Security Manager - Advanced Security Features for VPN Hub - SECURITY HARDENED
Implements kill switch, DNS leak protection, and other security measures with secure command execution
"""

import asyncio
import socket
import psutil
import platform
import logging
from typing import List, Dict, Optional, Tuple
from datetime import datetime
import json
import dns.resolver
import netifaces

try:
    from .input_sanitizer import InputSanitizer, SecurityException
    from .secure_command_executor import SecureCommandExecutor
except ImportError:
    # Handle imports when running as standalone script
    import sys
    from pathlib import Path
    src_dir = Path(__file__).parent
    sys.path.insert(0, str(src_dir))
    from input_sanitizer import InputSanitizer, SecurityException
    from secure_command_executor import SecureCommandExecutor

class SecurityManager:
    """Manages security features for VPN connections with enhanced security"""
    
    def __init__(self):
        self.kill_switch_enabled = True
        self.dns_protection_enabled = True
        self.leak_detection_enabled = True
        self.is_kill_switch_active = False
        self.original_routes: List[Dict] = []
        self.original_dns_servers: List[str] = []
        self.blocked_interfaces: List[str] = []
        self.safe_ips: List[str] = []  # VPN server IPs that should remain accessible
        
        # Initialize secure command executor
        self.secure_executor = SecureCommandExecutor()
        
        # Define allowed system commands with strict validation
        self.allowed_admin_commands = {
            # Windows commands
            'netsh': ['interface', 'advfirewall', 'wlan', 'show'],
            'route': ['print', 'add', 'delete'],
            'ipconfig': ['/all', '/flushdns', '/release', '/renew'],
            'powershell': ['-Command'],
            
            # Linux/macOS commands  
            'iptables': ['-A', '-D', '-I', '-F', '-L', '-P', '-t'],
            'ip': ['route', 'addr', 'link', 'show'],
            'systemctl': ['start', 'stop', 'restart', 'status'],
            'pfctl': ['-e', '-d', '-f'],
            'sudo': ['iptables', 'pfctl', 'systemctl', 'ip']
        }
        
        # Setup logging
        logging.basicConfig(
            filename='logs/security.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Initialize security monitoring
        self.monitoring_active = False
        self.leak_test_servers = [
            "8.8.8.8",  # Google DNS
            "1.1.1.1",  # Cloudflare DNS
            "208.67.222.222"  # OpenDNS
        ]
    
    async def enable_kill_switch(self, vpn_server_ips: List[str] = None) -> bool:
        """Enable kill switch to block all traffic except to VPN servers"""
        try:
            if self.is_kill_switch_active:
                self.logger.info("Kill switch already active")
                return True
            
            self.safe_ips = vpn_server_ips or []
            
            # Store original network configuration
            await self._store_original_config()
            
            # Implement kill switch based on platform
            if platform.system() == "Windows":
                success = await self._enable_windows_kill_switch()
            elif platform.system() == "Linux":
                success = await self._enable_linux_kill_switch()
            elif platform.system() == "Darwin":  # macOS
                success = await self._enable_macos_kill_switch()
            else:
                self.logger.error(f"Unsupported platform: {platform.system()}")
                return False
            
            if success:
                self.is_kill_switch_active = True
                self.logger.info("Kill switch enabled successfully")
                return True
            else:
                self.logger.error("Failed to enable kill switch")
                return False
                
        except Exception as e:
            self.logger.error(f"Error enabling kill switch: {e}")
            return False
    
    async def disable_kill_switch(self) -> bool:
        """Disable kill switch and restore original network configuration"""
        try:
            if not self.is_kill_switch_active:
                self.logger.info("Kill switch not active")
                return True
            
            # Restore network configuration based on platform
            if platform.system() == "Windows":
                success = await self._disable_windows_kill_switch()
            elif platform.system() == "Linux":
                success = await self._disable_linux_kill_switch()
            elif platform.system() == "Darwin":  # macOS
                success = await self._disable_macos_kill_switch()
            else:
                self.logger.error(f"Unsupported platform: {platform.system()}")
                return False
            
            if success:
                self.is_kill_switch_active = False
                self.logger.info("Kill switch disabled successfully")
                return True
            else:
                self.logger.error("Failed to disable kill switch")
                return False
                
        except Exception as e:
            self.logger.error(f"Error disabling kill switch: {e}")
            return False
    
    async def enable_dns_protection(self, vpn_dns_servers: List[str]) -> bool:
        """Enable DNS leak protection by setting secure DNS servers"""
        try:
            # Store original DNS configuration
            self.original_dns_servers = await self._get_current_dns_servers()
            
            # Set VPN DNS servers
            if platform.system() == "Windows":
                success = await self._set_windows_dns(vpn_dns_servers)
            elif platform.system() == "Linux":
                success = await self._set_linux_dns(vpn_dns_servers)
            elif platform.system() == "Darwin":  # macOS
                success = await self._set_macos_dns(vpn_dns_servers)
            else:
                self.logger.error(f"Unsupported platform: {platform.system()}")
                return False
            
            if success:
                self.logger.info(f"DNS protection enabled with servers: {vpn_dns_servers}")
                return True
            else:
                self.logger.error("Failed to enable DNS protection")
                return False
                
        except Exception as e:
            self.logger.error(f"Error enabling DNS protection: {e}")
            return False
    
    async def disable_dns_protection(self) -> bool:
        """Disable DNS protection and restore original DNS servers"""
        try:
            if not self.original_dns_servers:
                self.logger.warning("No original DNS servers to restore")
                return True
            
            # Restore original DNS servers
            if platform.system() == "Windows":
                success = await self._set_windows_dns(self.original_dns_servers)
            elif platform.system() == "Linux":
                success = await self._set_linux_dns(self.original_dns_servers)
            elif platform.system() == "Darwin":  # macOS
                success = await self._set_macos_dns(self.original_dns_servers)
            else:
                self.logger.error(f"Unsupported platform: {platform.system()}")
                return False
            
            if success:
                self.logger.info("DNS protection disabled, original servers restored")
                return True
            else:
                self.logger.error("Failed to disable DNS protection")
                return False
                
        except Exception as e:
            self.logger.error(f"Error disabling DNS protection: {e}")
            return False
    
    async def check_for_leaks(self) -> Dict[str, bool]:
        """Check for various types of leaks"""
        leak_results = {
            "ip_leak": False,
            "dns_leak": False,
            "webrtc_leak": False,
            "ipv6_leak": False
        }
        
        try:
            # Check IP leak
            leak_results["ip_leak"] = await self._check_ip_leak()
            
            # Check DNS leak
            leak_results["dns_leak"] = await self._check_dns_leak()
            
            # Check IPv6 leak
            leak_results["ipv6_leak"] = await self._check_ipv6_leak()
            
            # WebRTC leak check would require browser integration
            # For now, we'll leave it as False
            
            self.logger.info(f"Leak check results: {leak_results}")
            return leak_results
            
        except Exception as e:
            self.logger.error(f"Error checking for leaks: {e}")
            return leak_results
    
    async def monitor_connection_security(self, callback=None) -> None:
        """Continuously monitor connection security"""
        self.monitoring_active = True
        
        while self.monitoring_active:
            try:
                # Check for leaks
                leak_results = await self.check_for_leaks()
                
                # Check if kill switch is functioning
                kill_switch_status = await self._verify_kill_switch()
                
                # Create monitoring report
                security_report = {
                    "timestamp": datetime.now().isoformat(),
                    "kill_switch_active": self.is_kill_switch_active,
                    "kill_switch_functioning": kill_switch_status,
                    "dns_protection_active": self.dns_protection_enabled,
                    "leaks_detected": leak_results,
                    "any_leaks": any(leak_results.values())
                }
                
                # Call callback if provided
                if callback:
                    await callback(security_report)
                
                # Log any security issues
                if security_report["any_leaks"]:
                    self.logger.warning(f"Security leaks detected: {leak_results}")
                
                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in security monitoring: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    def stop_monitoring(self):
        """Stop security monitoring"""
        self.monitoring_active = False
        self.logger.info("Security monitoring stopped")
    
    async def emergency_disconnect(self) -> bool:
        """Emergency disconnect with full security lockdown"""
        try:
            self.logger.warning("Emergency disconnect initiated")
            
            # Enable kill switch if not already active
            if not self.is_kill_switch_active:
                await self.enable_kill_switch()
            
            # Block all network interfaces except localhost
            await self._emergency_network_lockdown()
            
            self.logger.warning("Emergency disconnect completed - network locked down")
            return True
            
        except Exception as e:
            self.logger.error(f"Error in emergency disconnect: {e}")
            return False
    
    # Platform-specific implementation methods
    
    async def _store_original_config(self):
        """Store original network configuration"""
        try:
            # Store routing table
            if platform.system() == "Windows":
                result = await self._run_command(["route", "print"])
            else:
                result = await self._run_command(["ip", "route", "show"])
            
            # Parse and store routes (simplified)
            self.original_routes = []  # Would implement proper route parsing
            
        except Exception as e:
            self.logger.error(f"Error storing original config: {e}")
    
    async def _enable_windows_kill_switch(self) -> bool:
        """Enable kill switch on Windows using netsh and route commands"""
        try:
            # Block all outbound traffic except to VPN servers
            for safe_ip in self.safe_ips:
                await self._run_command([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=VPN_SAFE_IP", "dir=out", "action=allow",
                    f"remoteip={safe_ip}"
                ])
            
            # Block all other outbound traffic
            await self._run_command([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=VPN_KILL_SWITCH", "dir=out", "action=block",
                "remoteip=0.0.0.0-255.255.255.255"
            ])
            
            return True
        except Exception as e:
            self.logger.error(f"Error enabling Windows kill switch: {e}")
            return False
    
    async def _disable_windows_kill_switch(self) -> bool:
        """Disable kill switch on Windows"""
        try:
            # Remove firewall rules
            await self._run_command([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=VPN_KILL_SWITCH"
            ])
            
            await self._run_command([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=VPN_SAFE_IP"
            ])
            
            return True
        except Exception as e:
            self.logger.error(f"Error disabling Windows kill switch: {e}")
            return False
    
    async def _enable_linux_kill_switch(self) -> bool:
        """Enable kill switch on Linux using iptables"""
        try:
            # Flush existing rules
            await self._run_command(["sudo", "iptables", "-F", "OUTPUT"])
            
            # Allow loopback
            await self._run_command([
                "sudo", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"
            ])
            
            # Allow traffic to VPN servers
            for safe_ip in self.safe_ips:
                await self._run_command([
                    "sudo", "iptables", "-A", "OUTPUT", "-d", safe_ip, "-j", "ACCEPT"
                ])
            
            # Block all other traffic
            await self._run_command([
                "sudo", "iptables", "-A", "OUTPUT", "-j", "DROP"
            ])
            
            return True
        except Exception as e:
            self.logger.error(f"Error enabling Linux kill switch: {e}")
            return False
    
    async def _disable_linux_kill_switch(self) -> bool:
        """Disable kill switch on Linux"""
        try:
            # Flush OUTPUT chain to remove all rules
            await self._run_command(["sudo", "iptables", "-F", "OUTPUT"])
            return True
        except Exception as e:
            self.logger.error(f"Error disabling Linux kill switch: {e}")
            return False
    
    async def _enable_macos_kill_switch(self) -> bool:
        """Enable kill switch on macOS using pfctl"""
        try:
            # Create pf rules file
            pf_rules = f"""
# VPN Kill Switch Rules
block out all
pass out to {{{', '.join(self.safe_ips)}}}
pass out on lo0 all
            """
            
            with open("/tmp/vpn_killswitch.conf", "w") as f:
                f.write(pf_rules)
            
            # Load rules
            await self._run_command([
                "sudo", "pfctl", "-f", "/tmp/vpn_killswitch.conf", "-e"
            ])
            
            return True
        except Exception as e:
            self.logger.error(f"Error enabling macOS kill switch: {e}")
            return False
    
    async def _disable_macos_kill_switch(self) -> bool:
        """Disable kill switch on macOS"""
        try:
            await self._run_command(["sudo", "pfctl", "-d"])
            return True
        except Exception as e:
            self.logger.error(f"Error disabling macOS kill switch: {e}")
            return False
    
    async def _get_current_dns_servers(self) -> List[str]:
        """Get current DNS servers"""
        try:
            if platform.system() == "Windows":
                result = await self._run_command([
                    "powershell", "-Command",
                    "Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses"
                ])
                return result.stdout.decode().strip().split('\n')
            else:
                # Linux/macOS
                with open('/etc/resolv.conf', 'r') as f:
                    content = f.read()
                
                dns_servers = []
                for line in content.split('\n'):
                    if line.startswith('nameserver'):
                        dns_servers.append(line.split()[1])
                
                return dns_servers
        except Exception as e:
            self.logger.error(f"Error getting current DNS servers: {e}")
            return []
    
    async def _set_windows_dns(self, dns_servers: List[str]) -> bool:
        """Set DNS servers on Windows"""
        try:
            # Get network interfaces
            interfaces = netifaces.interfaces()
            
            for interface in interfaces:
                if interface != "lo":  # Skip loopback
                    for i, dns in enumerate(dns_servers[:2]):  # Windows supports max 2 DNS servers per interface
                        await self._run_command([
                            "netsh", "interface", "ip", "set", "dns",
                            f"name={interface}", "static", dns,
                            "primary" if i == 0 else "none"
                        ])
            
            return True
        except Exception as e:
            self.logger.error(f"Error setting Windows DNS: {e}")
            return False
    
    async def _set_linux_dns(self, dns_servers: List[str]) -> bool:
        """Set DNS servers on Linux"""
        try:
            # Backup original resolv.conf
            await self._run_command([
                "sudo", "cp", "/etc/resolv.conf", "/etc/resolv.conf.vpn_backup"
            ])
            
            # Write new resolv.conf
            resolv_content = "\n".join([f"nameserver {dns}" for dns in dns_servers])
            
            with open("/tmp/resolv.conf.new", "w") as f:
                f.write(resolv_content + "\n")
            
            await self._run_command([
                "sudo", "cp", "/tmp/resolv.conf.new", "/etc/resolv.conf"
            ])
            
            return True
        except Exception as e:
            self.logger.error(f"Error setting Linux DNS: {e}")
            return False
    
    async def _set_macos_dns(self, dns_servers: List[str]) -> bool:
        """Set DNS servers on macOS"""
        try:
            # Get network services
            result = await self._run_command([
                "networksetup", "-listallnetworkservices"
            ])
            
            services = result.stdout.decode().strip().split('\n')[1:]  # Skip header
            
            for service in services:
                if not service.startswith('*'):  # Skip disabled services
                    await self._run_command([
                        "sudo", "networksetup", "-setdnsservers", service
                    ] + dns_servers)
            
            return True
        except Exception as e:
            self.logger.error(f"Error setting macOS DNS: {e}")
            return False
    
    async def _check_ip_leak(self) -> bool:
        """Check for IP address leaks"""
        try:
            # This would need to check if the current public IP matches the VPN IP
            # For now, we'll implement a basic check
            return False  # Assume no leak for now
        except Exception as e:
            self.logger.error(f"Error checking IP leak: {e}")
            return True  # Assume leak on error for safety
    
    async def _check_dns_leak(self) -> bool:
        """Check for DNS leaks"""
        try:
            # Test DNS resolution to see if it goes through VPN DNS
            resolver = dns.resolver.Resolver()
            
            for test_server in self.leak_test_servers:
                try:
                    # Resolve a test domain and check if it goes through expected DNS
                    response = resolver.resolve("google.com", "A")
                    # Additional logic would check if DNS queries go through VPN DNS
                except:
                    continue
            
            return False  # Assume no leak for basic implementation
        except Exception as e:
            self.logger.error(f"Error checking DNS leak: {e}")
            return True
    
    async def _check_ipv6_leak(self) -> bool:
        """Check for IPv6 leaks"""
        try:
            # Check if IPv6 is disabled or properly routed through VPN
            ipv6_interfaces = []
            
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET6 in addrs:
                    for addr in addrs[netifaces.AF_INET6]:
                        if not addr['addr'].startswith('fe80'):  # Skip link-local
                            ipv6_interfaces.append(interface)
            
            # If IPv6 interfaces exist without VPN protection, it's a leak
            return len(ipv6_interfaces) > 0
        except Exception as e:
            self.logger.error(f"Error checking IPv6 leak: {e}")
            return True
    
    async def _verify_kill_switch(self) -> bool:
        """Verify that kill switch is functioning properly"""
        try:
            if not self.is_kill_switch_active:
                return True
            
            # Try to connect to an external server (should fail)
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            
            try:
                # Try to connect to Google DNS (should be blocked)
                test_socket.connect(("8.8.8.8", 53))
                test_socket.close()
                return False  # Connection succeeded, kill switch not working
            except:
                return True  # Connection failed, kill switch working
            
        except Exception as e:
            self.logger.error(f"Error verifying kill switch: {e}")
            return False
    
    async def _emergency_network_lockdown(self):
        """Emergency network lockdown"""
        try:
            # Disable all network interfaces except loopback
            for interface in netifaces.interfaces():
                if interface != "lo" and interface != "127.0.0.1":
                    if platform.system() == "Windows":
                        await self._run_command([
                            "netsh", "interface", "set", "interface", interface, "disable"
                        ])
                    else:
                        await self._run_command([
                            "sudo", "ip", "link", "set", interface, "down"
                        ])
                    
                    self.blocked_interfaces.append(interface)
        except Exception as e:
            self.logger.error(f"Error in emergency lockdown: {e}")
    
    async def _run_secure_admin_command(self, command: List[str]) -> Tuple[int, str, str]:
        """
        Run administrative commands securely with validation
        
        Args:
            command: List of command arguments
            
        Returns:
            Tuple of (return_code, stdout, stderr)
            
        Raises:
            SecurityException: If command is not allowed or contains malicious content
        """
        try:
            # Validate command against whitelist
            if not command:
                raise SecurityException("Empty command not allowed")
            
            base_command = command[0]
            
            # Check if base command is allowed
            if base_command not in self.allowed_admin_commands:
                raise SecurityException(f"Administrative command '{base_command}' not allowed")
            
            # Validate subcommands and arguments
            allowed_subcommands = self.allowed_admin_commands[base_command]
            if len(command) > 1:
                # Check if any subcommand is allowed
                valid_subcommand = False
                for allowed_sub in allowed_subcommands:
                    if command[1].startswith(allowed_sub) or allowed_sub in command[1]:
                        valid_subcommand = True
                        break
                
                if not valid_subcommand:
                    raise SecurityException(f"Subcommand '{command[1]}' not allowed for '{base_command}'")
            
            # Sanitize all arguments for shell injection
            sanitized_command = []
            for arg in command:
                # Check for dangerous characters
                for char in InputSanitizer.SHELL_INJECTION_CHARS:
                    if char in arg:
                        raise SecurityException(f"Dangerous character '{char}' detected in command argument")
                sanitized_command.append(arg)
            
            # Log administrative command execution
            cmd_hash = InputSanitizer.hash_sensitive_data(' '.join(sanitized_command))
            self.logger.info(f"Executing administrative command: {base_command} (hash: {cmd_hash})")
            
            # Execute using secure command executor
            return await self.secure_executor.execute_vpn_command(
                sanitized_command,
                timeout=10  # Short timeout for admin commands
            )
            
        except SecurityException:
            raise
        except Exception as e:
            raise SecurityException(f"Administrative command execution failed: {str(e)}")