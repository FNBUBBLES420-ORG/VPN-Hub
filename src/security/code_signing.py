"""
Code Signing and Integrity Verification Module

This module provides functionality for:
1. Signing Python files and executables
2. Verifying integrity of signed files
3. Digital signature validation
"""

import hashlib
import hmac
import os
import sys
import json
import base64
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import logging

from .input_sanitizer import SecurityException

class CodeSigningManager:
    """Manages code signing and integrity verification for VPN Hub application"""
    
    def __init__(self, key_store_path: Optional[str] = None):
        """
        Initialize code signing manager
        
        Args:
            key_store_path: Path to store signing keys (defaults to ~/.vpnhub/keys)
        """
        self.logger = logging.getLogger(__name__)
        
        # Set up key storage path
        if key_store_path:
            self.key_store_path = Path(key_store_path)
        else:
            home_dir = Path.home()
            self.key_store_path = home_dir / '.vpnhub' / 'keys'
            
        self.key_store_path.mkdir(parents=True, exist_ok=True)
        
        # Ensure key store has proper permissions (owner only)
        if sys.platform != "win32":
            os.chmod(self.key_store_path, 0o700)
            
        self.private_key_path = self.key_store_path / 'signing_key.pem'
        self.public_key_path = self.key_store_path / 'public_key.pem'
        self.signatures_file = self.key_store_path / 'signatures.json'
        
        # Initialize or load keys
        self._ensure_signing_keys()
        
    def _ensure_signing_keys(self) -> None:
        """Ensure signing keys exist, generate if necessary"""
        try:
            if not self.private_key_path.exists() or not self.public_key_path.exists():
                self.logger.info("Generating new signing keys...")
                self._generate_signing_keys()
            else:
                # Verify key integrity
                try:
                    self._load_private_key()
                    self._load_public_key()
                    self.logger.info("Loaded existing signing keys")
                except Exception as e:
                    self.logger.warning(f"Key verification failed, regenerating: {e}")
                    self._generate_signing_keys()
        except Exception as e:
            raise SecurityException(f"Failed to initialize signing keys: {e}")
            
    def _generate_signing_keys(self) -> None:
        """Generate RSA key pair for code signing"""
        try:
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Write keys to files with secure permissions
            with open(self.private_key_path, 'wb') as f:
                f.write(private_pem)
            with open(self.public_key_path, 'wb') as f:
                f.write(public_pem)
                
            # Set secure permissions
            if sys.platform != "win32":
                os.chmod(self.private_key_path, 0o600)
                os.chmod(self.public_key_path, 0o644)
            else:
                # Windows: Remove inheritance and set owner-only access
                import subprocess
                subprocess.run([
                    'icacls', str(self.private_key_path), 
                    '/inheritance:r', '/grant:r', f'{os.getlogin()}:(R,W)'
                ], capture_output=True)
                
            self.logger.info("Successfully generated signing keys")
            
        except Exception as e:
            raise SecurityException(f"Key generation failed: {e}")
            
    def _load_private_key(self):
        """Load private key for signing"""
        try:
            with open(self.private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            return private_key
        except Exception as e:
            raise SecurityException(f"Failed to load private key: {e}")
            
    def _load_public_key(self):
        """Load public key for verification"""
        try:
            with open(self.public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(),
                    backend=default_backend()
                )
            return public_key
        except Exception as e:
            raise SecurityException(f"Failed to load public key: {e}")
            
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            raise SecurityException(f"Failed to calculate file hash: {e}")
            
    def sign_file(self, file_path: Union[str, Path]) -> Dict[str, str]:
        """
        Sign a file and return signature information
        
        Args:
            file_path: Path to file to sign
            
        Returns:
            Dictionary containing signature information
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise SecurityException(f"File not found: {file_path}")
                
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            
            # Load private key
            private_key = self._load_private_key()
            
            # Create signature payload
            timestamp = int(time.time())
            payload = {
                'file_path': str(file_path.absolute()),
                'file_hash': file_hash,
                'timestamp': timestamp,
                'signer': 'VPNHub_CodeSigning'
            }
            payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
            
            # Sign the payload
            signature = private_key.sign(
                payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Encode signature
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            # Prepare signature info
            signature_info = {
                'file_path': str(file_path.absolute()),
                'file_hash': file_hash,
                'signature': signature_b64,
                'timestamp': timestamp,
                'algorithm': 'RSA-PSS-SHA256'
            }
            
            # Store signature
            self._store_signature(file_path, signature_info)
            
            self.logger.info(f"Successfully signed file: {file_path}")
            return signature_info
            
        except Exception as e:
            self.logger.error(f"File signing failed: {e}")
            raise SecurityException(f"File signing failed: {e}")
            
    def verify_file(self, file_path: Union[str, Path]) -> bool:
        """
        Verify file signature and integrity
        
        Args:
            file_path: Path to file to verify
            
        Returns:
            True if file is valid and signature matches
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise SecurityException(f"File not found: {file_path}")
                
            # Load stored signature
            signature_info = self._load_signature(file_path)
            if not signature_info:
                self.logger.warning(f"No signature found for file: {file_path}")
                return False
                
            # Calculate current file hash
            current_hash = self._calculate_file_hash(file_path)
            
            # Check if file has been modified
            if current_hash != signature_info['file_hash']:
                self.logger.warning(f"File hash mismatch for: {file_path}")
                return False
                
            # Load public key
            public_key = self._load_public_key()
            
            # Reconstruct payload
            payload = {
                'file_path': signature_info['file_path'],
                'file_hash': signature_info['file_hash'],
                'timestamp': signature_info['timestamp'],
                'signer': 'VPNHub_CodeSigning'
            }
            payload_bytes = json.dumps(payload, sort_keys=True).encode('utf-8')
            
            # Decode signature
            signature = base64.b64decode(signature_info['signature'])
            
            # Verify signature
            try:
                public_key.verify(
                    signature,
                    payload_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                self.logger.info(f"File signature verified: {file_path}")
                return True
                
            except Exception as verify_error:
                self.logger.warning(f"Signature verification failed for {file_path}: {verify_error}")
                return False
                
        except Exception as e:
            self.logger.error(f"File verification failed: {e}")
            return False
            
    def _store_signature(self, file_path: Path, signature_info: Dict[str, str]) -> None:
        """Store signature information"""
        try:
            # Load existing signatures
            signatures = {}
            if self.signatures_file.exists():
                with open(self.signatures_file, 'r') as f:
                    signatures = json.load(f)
                    
            # Add new signature
            signatures[str(file_path.absolute())] = signature_info
            
            # Save signatures
            with open(self.signatures_file, 'w') as f:
                json.dump(signatures, f, indent=2)
                
            # Set secure permissions
            if sys.platform != "win32":
                os.chmod(self.signatures_file, 0o600)
                
        except Exception as e:
            raise SecurityException(f"Failed to store signature: {e}")
            
    def _load_signature(self, file_path: Path) -> Optional[Dict[str, str]]:
        """Load signature information for file"""
        try:
            if not self.signatures_file.exists():
                return None
                
            with open(self.signatures_file, 'r') as f:
                signatures = json.load(f)
                
            return signatures.get(str(file_path.absolute()))
            
        except Exception as e:
            self.logger.error(f"Failed to load signature: {e}")
            return None
            
    def sign_python_files(self, directory: Union[str, Path]) -> List[Dict[str, str]]:
        """
        Sign all Python files in a directory recursively
        
        Args:
            directory: Directory to scan for Python files
            
        Returns:
            List of signature information for each signed file
        """
        try:
            directory = Path(directory)
            if not directory.exists():
                raise SecurityException(f"Directory not found: {directory}")
                
            signed_files = []
            
            # Find all Python files
            for py_file in directory.rglob('*.py'):
                try:
                    signature_info = self.sign_file(py_file)
                    signed_files.append(signature_info)
                except Exception as e:
                    self.logger.warning(f"Failed to sign {py_file}: {e}")
                    
            self.logger.info(f"Signed {len(signed_files)} Python files in {directory}")
            return signed_files
            
        except Exception as e:
            raise SecurityException(f"Batch signing failed: {e}")
            
    def verify_python_files(self, directory: Union[str, Path]) -> Tuple[List[Path], List[Path]]:
        """
        Verify all Python files in a directory
        
        Args:
            directory: Directory to scan for Python files
            
        Returns:
            Tuple of (valid_files, invalid_files) - unsigned files are not included in either list
        """
        try:
            directory = Path(directory)
            if not directory.exists():
                raise SecurityException(f"Directory not found: {directory}")
                
            valid_files = []
            invalid_files = []
            
            # Check all Python files
            for py_file in directory.rglob('*.py'):
                try:
                    # Check if file has a signature first
                    signature_info = self._load_signature(py_file)
                    if signature_info:
                        # File has a signature, verify it
                        if self.verify_file(py_file):
                            valid_files.append(py_file)
                        else:
                            invalid_files.append(py_file)
                    # If no signature, file is unsigned - don't add to either list
                except Exception as e:
                    self.logger.warning(f"Failed to verify {py_file}: {e}")
                    # On error, treat as invalid if it had a signature
                    signature_info = self._load_signature(py_file)
                    if signature_info:
                        invalid_files.append(py_file)
                    
            self.logger.info(f"Verified {len(valid_files)} valid files, {len(invalid_files)} invalid files")
            return valid_files, invalid_files
            
        except Exception as e:
            raise SecurityException(f"Batch verification failed: {e}")
            
    def get_file_integrity_report(self, directory: Union[str, Path]) -> Dict[str, any]:
        """
        Generate comprehensive integrity report for directory
        
        Args:
            directory: Directory to analyze
            
        Returns:
            Dictionary containing integrity report
        """
        try:
            directory = Path(directory)
            valid_files, invalid_files = self.verify_python_files(directory)
            
            # Find unsigned files
            all_py_files = list(directory.rglob('*.py'))
            signed_files = valid_files + invalid_files
            unsigned_files = [f for f in all_py_files if f not in signed_files]
            
            report = {
                'timestamp': int(time.time()),
                'directory': str(directory.absolute()),
                'total_python_files': len(all_py_files),
                'valid_signatures': len(valid_files),
                'invalid_signatures': len(invalid_files),
                'unsigned_files': len(unsigned_files),
                'integrity_score': (len(valid_files) / len(all_py_files)) * 100 if all_py_files else 100,
                'valid_files': [str(f) for f in valid_files],
                'invalid_files': [str(f) for f in invalid_files],
                'unsigned_files_list': [str(f) for f in unsigned_files]
            }
            
            return report
            
        except Exception as e:
            raise SecurityException(f"Integrity report generation failed: {e}")

# Utility functions for easy access
def sign_vpn_hub_files(base_directory: str = None) -> None:
    """Sign all VPN Hub Python files"""
    if not base_directory:
        base_directory = Path(__file__).parent.parent.parent
        
    signer = CodeSigningManager()
    signer.sign_python_files(base_directory)
    
def verify_vpn_hub_integrity(base_directory: str = None) -> Dict[str, any]:
    """Verify VPN Hub file integrity"""
    if not base_directory:
        base_directory = Path(__file__).parent.parent.parent
        
    signer = CodeSigningManager()
    return signer.get_file_integrity_report(base_directory)