"""
Run this script to test the VPN Hub installation and basic functionality
"""

import os
import sys
import subprocess
import importlib
from pathlib import Path

def test_python_version():
    """Test if Python version is compatible"""
    print("Testing Python version...")
    
    if sys.version_info < (3, 8):
        print(f"❌ Python 3.8+ required, found {sys.version}")
        return False
    else:
        print(f"✅ Python {sys.version.split()[0]} is compatible")
        return True

def test_dependencies():
    """Test if all required dependencies are installed"""
    print("\nTesting dependencies...")
    
    required_packages = [
        'PyQt5',
        'cryptography', 
        'psutil',
        'aiohttp',
        'dnspython',
        'netifaces',
        'keyring',
        'requests'
    ]
    
    failed_imports = []
    
    for package in required_packages:
        try:
            # Handle special cases for package names
            if package == 'PyQt5':
                importlib.import_module('PyQt5.QtWidgets')
            elif package == 'dnspython':
                importlib.import_module('dns.resolver')
            else:
                importlib.import_module(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} - Missing")
            failed_imports.append(package)
    
    if failed_imports:
        print(f"\n❌ Missing packages: {', '.join(failed_imports)}")
        print("Install with: pip install -r requirements.txt")
        return False
    else:
        print("✅ All dependencies are installed")
        return True

def test_file_structure():
    """Test if all required files and directories exist"""
    print("\nTesting file structure...")
    
    base_dir = Path(__file__).parent
    required_paths = [
        "src/main.py",
        "src/core/vpn_interface.py",
        "src/core/connection_manager.py",
        "src/core/config_manager.py",
        "src/providers/__init__.py",
        "src/providers/nordvpn.py",
        "src/providers/expressvpn.py",
        "src/providers/surfshark.py",
        "src/gui/main_window.py",
        "src/security/security_manager.py",
        "requirements.txt",
        "README.md"
    ]
    
    missing_files = []
    
    for path in required_paths:
        full_path = base_dir / path
        if full_path.exists():
            print(f"✅ {path}")
        else:
            print(f"❌ {path} - Missing")
            missing_files.append(path)
    
    if missing_files:
        print(f"\n❌ Missing files: {missing_files}")
        return False
    else:
        print("✅ All required files are present")
        return True

def test_imports():
    """Test if core modules can be imported"""
    print("\nTesting module imports...")
    
    # Add src to path
    src_dir = Path(__file__).parent / "src"
    sys.path.insert(0, str(src_dir))
    
    modules_to_test = [
        "core.vpn_interface",
        "core.connection_manager", 
        "core.config_manager",
        "providers",
        "security.security_manager"
    ]
    
    failed_imports = []
    
    for module in modules_to_test:
        try:
            importlib.import_module(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module} - {str(e)}")
            failed_imports.append(module)
    
    if failed_imports:
        print(f"\n❌ Failed to import: {failed_imports}")
        return False
    else:
        print("✅ All core modules import successfully")
        return True

def test_configuration():
    """Test configuration manager functionality"""
    print("\nTesting configuration management...")
    
    try:
        # Add src to path
        src_dir = Path(__file__).parent / "src"
        sys.path.insert(0, str(src_dir))
        
        from core.config_manager import ConfigurationManager
        import tempfile
        import shutil
        
        # Create temporary directory for testing
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Initialize config manager
            config_manager = ConfigurationManager(config_dir=temp_dir)
            print("✅ Configuration manager initialized")
            
            # Test adding a provider
            provider_config = {
                "name": "Test Provider",
                "username": "test_user", 
                "password": "test_pass",
                "enabled": True
            }
            
            success = config_manager.add_provider("test_provider", provider_config)
            if success:
                print("✅ Provider configuration added")
            else:
                print("❌ Failed to add provider configuration")
                return False
            
            # Test retrieving provider
            retrieved = config_manager.get_provider("test_provider")
            if retrieved and retrieved["name"] == "Test Provider":
                print("✅ Provider configuration retrieved")
            else:
                print("❌ Failed to retrieve provider configuration")
                return False
            
            print("✅ Configuration management working")
            return True
            
        finally:
            # Clean up temp directory
            shutil.rmtree(temp_dir)
            
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_gui_imports():
    """Test if GUI components can be imported"""
    print("\nTesting GUI imports...")
    
    try:
        # Test PyQt5 imports
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtCore import Qt
        from PyQt5.QtGui import QIcon
        print("✅ PyQt5 core components")
        
        # Add src to path
        src_dir = Path(__file__).parent / "src"
        sys.path.insert(0, str(src_dir))
        
        # Test GUI module import
        import gui.main_window
        print("✅ VPN Hub GUI module")
        
        print("✅ GUI components ready")
        return True
        
    except ImportError as e:
        print(f"❌ GUI import failed: {e}")
        return False

def test_security_features():
    """Test if security features are available"""
    print("\nTesting security features...")
    
    try:
        # Add src to path
        src_dir = Path(__file__).parent / "src"
        sys.path.insert(0, str(src_dir))
        
        from security.security_manager import SecurityManager
        
        # Initialize security manager
        security_manager = SecurityManager()
        print("✅ Security manager initialized")
        
        # Test basic functionality
        if hasattr(security_manager, 'kill_switch_enabled'):
            print("✅ Kill switch feature available")
        
        if hasattr(security_manager, 'dns_protection_enabled'):
            print("✅ DNS protection feature available")
        
        print("✅ Security features ready")
        return True
        
    except Exception as e:
        print(f"❌ Security test failed: {e}")
        return False

def test_application_startup():
    """Test if the main application can start (without GUI)"""
    print("\nTesting application startup...")
    
    try:
        # Add src to path
        src_dir = Path(__file__).parent / "src"
        sys.path.insert(0, str(src_dir))
        
        # Test core components initialization
        from core.connection_manager import VPNConnectionManager
        from core.config_manager import ConfigurationManager
        
        # Test initialization without actually starting GUI
        connection_manager = VPNConnectionManager()
        print("✅ Connection manager initialized")
        
        config_manager = ConfigurationManager()
        print("✅ Configuration manager initialized")
        
        print("✅ Application components ready")
        return True
        
    except Exception as e:
        print(f"❌ Application startup test failed: {e}")
        return False

def run_comprehensive_test():
    """Run all tests and provide summary"""
    print("VPN Hub Installation Test")
    print("=" * 50)
    
    tests = [
        ("Python Version", test_python_version),
        ("Dependencies", test_dependencies),
        ("File Structure", test_file_structure),
        ("Module Imports", test_imports),
        ("Configuration", test_configuration),
        ("GUI Components", test_gui_imports),
        ("Security Features", test_security_features),
        ("Application Startup", test_application_startup)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    
    passed = 0
    failed = 0
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<20} {status}")
        
        if result:
            passed += 1
        else:
            failed += 1
    
    print(f"\nTotal: {len(results)} tests")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if failed == 0:
        print("\n🎉 All tests passed! VPN Hub is ready to use.")
        print("Run 'python src/main.py' to start the application.")
        return True
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please fix the issues above.")
        print("Refer to INSTALL.md for detailed installation instructions.")
        return False

if __name__ == "__main__":
    success = run_comprehensive_test()
    sys.exit(0 if success else 1)