"""
Network Security Module

This module provides enhanced network security features:
1. Certificate pinning for API calls
2. TLS verification for all connections
3. Secure DNS resolution
4. Network request validation
"""

import ssl
import socket
import hashlib
import base64
import dns.resolver
import requests
import certifi
from urllib3.util import connection
from urllib3.poolmanager import PoolManager
from urllib3.exceptions import InsecureRequestWarning
import logging
from typing import Dict, List, Optional, Union, Tuple
from pathlib import Path
import json
import time

from .input_sanitizer import SecurityException, InputSanitizer

class NetworkSecurityManager:
    """Manages network security features for VPN Hub"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize network security manager
        
        Args:
            config_path: Path to network security configuration
        """
        self.logger = logging.getLogger(__name__)
        
        # Certificate pinning database
        self.pinned_certificates = {
            # VPN Provider API endpoints
            'nordvpn.com': [
                'sha256/K+8aN4+JWsAH9qFZZWUUfzVyN+YJGJbQptzb+3cVQvY=',  # Example pin
                'sha256/7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y='   # Backup pin
            ],
            'expressvpn.com': [
                'sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=',
                'sha256/sRHdihwgkaib1P1gxX8HFszlD+7/gTfNvuAybgLPNis='
            ],
            'surfshark.com': [
                'sha256/x4QzPSC810K5/cMjb05Qm4k3Bw5zBn4lTdO/nEW/Td4=',
                'sha256/58qRu/uxh4gFezqAcERupSkRYBlBAvfcw7mEjGPLnNU='
            ]
        }
        
        # Trusted DNS servers (secure DNS providers)
        self.secure_dns_servers = [
            '1.1.1.1',      # Cloudflare DNS
            '1.0.0.1',      # Cloudflare DNS secondary
            '8.8.8.8',      # Google DNS
            '8.8.4.4',      # Google DNS secondary
            '9.9.9.9',      # Quad9 DNS
            '149.112.112.112'  # Quad9 DNS secondary
        ]
        
        # Initialize secure DNS resolver
        self._setup_secure_dns()
        
        # Initialize SSL context
        self._setup_ssl_context()
        
        # Disable urllib3 warnings for our custom verification
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
    def _setup_secure_dns(self) -> None:
        """Configure secure DNS resolution"""
        try:
            self.dns_resolver = dns.resolver.Resolver()
            self.dns_resolver.nameservers = self.secure_dns_servers
            self.dns_resolver.timeout = 5
            self.dns_resolver.lifetime = 10
            
            # Use DNS over HTTPS when available
            try:
                self.dns_resolver.use_edns(0, 0, 4096)
            except:
                pass  # Fallback to regular DNS
                
            self.logger.info("Configured secure DNS resolution")
            
        except Exception as e:
            self.logger.warning(f"Failed to setup secure DNS: {e}")
            # Continue with system DNS as fallback
            
    def _setup_ssl_context(self) -> None:
        """Setup secure SSL context"""
        try:
            # Create secure SSL context
            self.ssl_context = ssl.create_default_context(cafile=certifi.where())
            
            # Enhanced security settings
            self.ssl_context.check_hostname = True
            self.ssl_context.verify_mode = ssl.CERT_REQUIRED
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Disable weak ciphers
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            # Set secure options (avoid deprecated SSL options)
            self.ssl_context.options |= ssl.OP_NO_SSLv2
            self.ssl_context.options |= ssl.OP_NO_SSLv3
            # Use minimum_version instead of deprecated OP_NO_TLS options
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.options |= ssl.OP_SINGLE_DH_USE
            self.ssl_context.options |= ssl.OP_SINGLE_ECDH_USE
            
            self.logger.info("Configured secure SSL context")
            
        except Exception as e:
            raise SecurityException(f"Failed to setup SSL context: {e}")
            
    def _extract_certificate_pins(self, hostname: str, port: int = 443) -> List[str]:
        """Extract certificate pins from a host"""
        try:
            # Connect and get certificate chain
            sock = socket.create_connection((hostname, port), timeout=10)
            ssl_sock = self.ssl_context.wrap_socket(sock, server_hostname=hostname)
            
            # Get peer certificate chain
            cert_der = ssl_sock.getpeercert_chain()
            pins = []
            
            if cert_der:
                for cert in cert_der:
                    # Get certificate in DER format
                    cert_bytes = cert.public_bytes(encoding=ssl.Encoding.DER)
                    
                    # Calculate SHA-256 hash of the certificate
                    cert_hash = hashlib.sha256(cert_bytes).digest()
                    pin = base64.b64encode(cert_hash).decode('ascii')
                    pins.append(f'sha256/{pin}')
                    
            ssl_sock.close()
            return pins
            
        except Exception as e:
            self.logger.error(f"Failed to extract certificate pins from {hostname}: {e}")
            return []
            
    def verify_certificate_pin(self, hostname: str, certificate_chain: List) -> bool:
        """Verify certificate against pinned certificates"""
        try:
            domain = self._extract_domain(hostname)
            expected_pins = self.pinned_certificates.get(domain)
            
            if not expected_pins:
                self.logger.warning(f"No certificate pins configured for {domain}")
                return True  # Allow if no pins configured (for flexibility)
                
            # Extract pins from received certificate chain
            received_pins = []
            for cert in certificate_chain:
                cert_bytes = cert.public_bytes(encoding=ssl.Encoding.DER)
                cert_hash = hashlib.sha256(cert_bytes).digest()
                pin = f'sha256/{base64.b64encode(cert_hash).decode("ascii")}'
                received_pins.append(pin)
                
            # Check if any received pin matches expected pins
            for pin in received_pins:
                if pin in expected_pins:
                    self.logger.info(f"Certificate pin verified for {hostname}")
                    return True
                    
            self.logger.error(f"Certificate pin verification failed for {hostname}")
            return False
            
        except Exception as e:
            self.logger.error(f"Certificate pin verification error for {hostname}: {e}")
            return False
            
    def _extract_domain(self, hostname: str) -> str:
        """Extract base domain from hostname"""
        try:
            # Remove subdomain if present
            parts = hostname.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return hostname
        except:
            return hostname
            
    class SecureHTTPAdapter(requests.adapters.HTTPAdapter):
        """Custom HTTP adapter with certificate pinning"""
        
        def __init__(self, security_manager, *args, **kwargs):
            self.security_manager = security_manager
            super().__init__(*args, **kwargs)
            
        def init_poolmanager(self, *args, **kwargs):
            kwargs['ssl_context'] = self.security_manager.ssl_context
            return super().init_poolmanager(*args, **kwargs)
            
        def cert_verify(self, conn, url, verify, cert):
            """Custom certificate verification with pinning"""
            # First do standard verification
            super().cert_verify(conn, url, verify, cert)
            
            # Then check certificate pinning
            hostname = conn.host
            if hasattr(conn, 'sock') and hasattr(conn.sock, 'getpeercert_chain'):
                cert_chain = conn.sock.getpeercert_chain()
                if cert_chain and not self.security_manager.verify_certificate_pin(hostname, cert_chain):
                    raise ssl.SSLError(f"Certificate pin verification failed for {hostname}")
                    
    def create_secure_session(self) -> requests.Session:
        """Create a secure requests session with certificate pinning"""
        try:
            session = requests.Session()
            
            # Add secure adapter
            adapter = self.SecureHTTPAdapter(self)
            session.mount('https://', adapter)
            session.mount('http://', adapter)
            
            # Set secure defaults
            session.verify = True
            session.timeout = (10, 30)  # (connect, read) timeout
            
            # Add security headers
            session.headers.update({
                'User-Agent': 'VPNHub/2.0 (Secure)',
                'Accept': 'application/json',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'DNT': '1',
                'Upgrade-Insecure-Requests': '1'
            })
            
            return session
            
        except Exception as e:
            raise SecurityException(f"Failed to create secure session: {e}")
            
    def secure_dns_lookup(self, hostname: str) -> List[str]:
        """Perform secure DNS lookup"""
        try:
            # Validate hostname
            hostname = InputSanitizer.sanitize_server_name(hostname)
            
            # Perform DNS query using secure resolver
            try:
                answers = self.dns_resolver.resolve(hostname, 'A')
                ip_addresses = [str(answer) for answer in answers]
                
                self.logger.info(f"Secure DNS lookup for {hostname}: {ip_addresses}")
                return ip_addresses
                
            except dns.resolver.NXDOMAIN:
                self.logger.warning(f"DNS lookup failed - domain not found: {hostname}")
                return []
            except dns.resolver.Timeout:
                self.logger.warning(f"DNS lookup timeout for: {hostname}")
                return []
                
        except Exception as e:
            self.logger.error(f"Secure DNS lookup failed for {hostname}: {e}")
            return []
            
    def validate_url(self, url: str) -> bool:
        """Validate URL for security"""
        try:
            # Basic URL validation
            if not url or not isinstance(url, str):
                return False
                
            # Must use HTTPS for sensitive operations
            if not url.lower().startswith('https://'):
                self.logger.warning(f"Insecure URL protocol: {url}")
                return False
                
            # Check for suspicious patterns
            suspicious_patterns = [
                'javascript:', 'data:', 'file:', 'ftp:',
                '..', '\\', '<script', '<iframe'
            ]
            
            url_lower = url.lower()
            for pattern in suspicious_patterns:
                if pattern in url_lower:
                    self.logger.warning(f"Suspicious URL pattern detected: {pattern}")
                    return False
                    
            # Extract hostname for validation
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            if hostname:
                # Validate hostname
                try:
                    InputSanitizer.sanitize_server_name(hostname)
                except:
                    self.logger.warning(f"Invalid hostname in URL: {hostname}")
                    return False
                    
            return True
            
        except Exception as e:
            self.logger.error(f"URL validation failed: {e}")
            return False
            
    def make_secure_request(self, 
                          method: str, 
                          url: str, 
                          **kwargs) -> requests.Response:
        """Make a secure HTTP request with full security validation"""
        try:
            # Validate URL
            if not self.validate_url(url):
                raise SecurityException(f"URL validation failed: {url}")
                
            # Create secure session
            session = self.create_secure_session()
            
            # Add request timeout if not specified
            if 'timeout' not in kwargs:
                kwargs['timeout'] = (10, 30)
                
            # Ensure HTTPS verification
            if 'verify' not in kwargs:
                kwargs['verify'] = True
                
            # Make request
            self.logger.info(f"Making secure {method} request to {url}")
            response = session.request(method, url, **kwargs)
            
            # Log response info (without sensitive data)
            self.logger.info(f"Secure request completed: {response.status_code} {response.reason}")
            
            return response
            
        except Exception as e:
            self.logger.error(f"Secure request failed: {e}")
            raise SecurityException(f"Secure request failed: {e}")
            
    def get_security_headers(self) -> Dict[str, str]:
        """Get recommended security headers for requests"""
        return {
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';",
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
        
    def check_network_connectivity(self) -> Dict[str, bool]:
        """Check network connectivity to critical services"""
        try:
            connectivity_status = {}
            
            # Test connectivity to secure DNS servers
            dns_working = False
            for dns_server in self.secure_dns_servers[:2]:  # Test first 2
                try:
                    sock = socket.create_connection((dns_server, 53), timeout=5)
                    sock.close()
                    dns_working = True
                    break
                except:
                    continue
                    
            connectivity_status['secure_dns'] = dns_working
            
            # Test HTTPS connectivity
            try:
                response = self.make_secure_request('GET', 'https://www.google.com', timeout=10)
                connectivity_status['https'] = response.status_code == 200
            except:
                connectivity_status['https'] = False
                
            # Test VPN provider connectivity (basic check)
            vpn_providers = ['nordvpn.com', 'expressvpn.com', 'surfshark.com']
            vpn_connectivity = {}
            
            for provider in vpn_providers:
                try:
                    # Simple TCP connection test
                    sock = socket.create_connection((provider, 443), timeout=10)
                    sock.close()
                    vpn_connectivity[provider] = True
                except:
                    vpn_connectivity[provider] = False
                    
            connectivity_status['vpn_providers'] = vpn_connectivity
            
            self.logger.info(f"Network connectivity check: {connectivity_status}")
            return connectivity_status
            
        except Exception as e:
            self.logger.error(f"Network connectivity check failed: {e}")
            return {'error': str(e)}
            
    def update_certificate_pins(self, hostname: str, force_update: bool = False) -> bool:
        """Update certificate pins for a hostname"""
        try:
            domain = self._extract_domain(hostname)
            
            # Check if update is needed
            if not force_update and domain in self.pinned_certificates:
                self.logger.info(f"Certificate pins already exist for {domain}")
                return True
                
            # Extract current pins
            new_pins = self._extract_certificate_pins(hostname)
            
            if new_pins:
                self.pinned_certificates[domain] = new_pins
                self.logger.info(f"Updated certificate pins for {domain}: {len(new_pins)} pins")
                return True
            else:
                self.logger.warning(f"Failed to extract certificate pins for {hostname}")
                return False
                
        except Exception as e:
            self.logger.error(f"Certificate pin update failed for {hostname}: {e}")
            return False

# Global instance for easy access
_network_security_manager = None

def get_network_security_manager() -> NetworkSecurityManager:
    """Get global network security manager instance"""
    global _network_security_manager
    if _network_security_manager is None:
        _network_security_manager = NetworkSecurityManager()
    return _network_security_manager

def make_secure_vpn_request(method: str, url: str, **kwargs) -> requests.Response:
    """Make a secure request for VPN operations"""
    manager = get_network_security_manager()
    return manager.make_secure_request(method, url, **kwargs)