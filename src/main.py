"""
VPN Hub - Professional Multi-Provider VPN Manager
Main application entry point
"""

import sys
import os
import asyncio
import logging
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).parent
sys.path.insert(0, str(src_dir))

try:
    from gui.main_window import main as gui_main
    from core.connection_manager import VPNConnectionManager
    from core.config_manager import ConfigurationManager
    from security.security_manager import SecurityManager
except ImportError:
    # Handle imports when running as standalone script
    import sys
    from pathlib import Path
    src_dir = Path(__file__).parent
    sys.path.insert(0, str(src_dir))
    
    from gui.main_window import main as gui_main
    from core.connection_manager import VPNConnectionManager
    from core.config_manager import ConfigurationManager
    from security.security_manager import SecurityManager

def setup_logging():
    """Setup application logging"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "vpn_hub.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def check_dependencies():
    """Check if all required dependencies are available"""
    required_packages = [
        ('PyQt5', 'PyQt5.QtWidgets'), 
        ('cryptography', 'cryptography'), 
        ('psutil', 'psutil'), 
        ('dnspython', 'dns.resolver'), 
        ('netifaces', 'netifaces'), 
        ('keyring', 'keyring'), 
        ('aiohttp', 'aiohttp')
    ]
    
    missing_packages = []
    
    for package_name, import_name in required_packages:
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(package_name)
    
    if missing_packages:
        print(f"Missing required packages: {', '.join(missing_packages)}")
        print("Please install them using: pip install -r requirements.txt")
        return False
    
    return True

def check_permissions():
    """Check if the application has necessary permissions"""
    import platform
    
    if platform.system() == "Windows":
        # Check if running as administrator for firewall rules
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("Warning: Administrator privileges recommended for full security features")
        except:
            pass
    
    elif platform.system() in ["Linux", "Darwin"]:
        # Check sudo access for iptables/pfctl
        if os.geteuid() != 0:
            print("Warning: Root privileges may be required for some security features")
    
    return True

def initialize_application():
    """Initialize application components"""
    try:
        # Setup logging
        setup_logging()
        logger = logging.getLogger(__name__)
        
        logger.info("Starting VPN Hub application")
        
        # Check dependencies
        if not check_dependencies():
            return False
        
        # Check permissions
        check_permissions()
        
        # Initialize configuration manager
        config_manager = ConfigurationManager()
        logger.info("Configuration manager initialized")
        
        # Initialize connection manager
        connection_manager = VPNConnectionManager()
        logger.info("Connection manager initialized")
        
        # Initialize security manager
        security_manager = SecurityManager()
        logger.info("Security manager initialized")
        
        logger.info("Application initialization completed successfully")
        return True
        
    except Exception as e:
        print(f"Error initializing application: {e}")
        return False

def main():
    """Main application entry point"""
    print("VPN Hub - Professional Multi-Provider VPN Manager")
    print("=" * 50)
    
    # Initialize application
    if not initialize_application():
        print("Failed to initialize application. Exiting.")
        sys.exit(1)
    
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--help" or sys.argv[1] == "-h":
            print_help()
            return
        elif sys.argv[1] == "--version" or sys.argv[1] == "-v":
            print("VPN Hub version 1.0.0")
            return
        elif sys.argv[1] == "--cli":
            print("CLI mode not yet implemented")
            return
    
    # Start GUI application
    try:
        print("Starting VPN Hub GUI...")
        sys.exit(gui_main())
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)

def print_help():
    """Print help information"""
    help_text = """
VPN Hub - Professional Multi-Provider VPN Manager

Usage: python main.py [options]

Options:
  -h, --help     Show this help message
  -v, --version  Show version information
  --cli          Start in CLI mode (not yet implemented)

Features:
  - Multi-provider VPN support (NordVPN, ExpressVPN, Surfshark, etc.)
  - Professional GUI interface
  - Advanced security features (Kill switch, DNS protection)
  - Connection monitoring and leak detection
  - Secure credential storage
  - Connection history and statistics

For more information, see README.md
    """
    print(help_text)

if __name__ == "__main__":
    main()