"""
Professional VPN Hub GUI - Main Application Window
Modern, user-friendly interface for managing multiple VPN providers
"""

import sys
import asyncio
import json
from typing import Dict, List, Optional
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QLabel, QPushButton, QComboBox, QListWidget, 
    QListWidgetItem, QTextEdit, QProgressBar, QSystemTrayIcon,
    QMenu, QAction, QMessageBox, QDialog, QFormLayout, QLineEdit,
    QCheckBox, QSpinBox, QGroupBox, QGridLayout, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QFrame
)
from PyQt5.QtCore import (
    Qt, QTimer, QThread, pyqtSignal, QSettings, QSize
)
from PyQt5.QtGui import (
    QIcon, QPixmap, QFont, QPalette, QColor, QMovie
)

try:
    from ..core.connection_manager import VPNConnectionManager
    from ..core.vpn_interface import ConnectionStatus, ProtocolType, ServerInfo
    from ..security.input_sanitizer import InputSanitizer, SecurityException
except ImportError:
    # Handle imports when running as standalone script
    import sys
    from pathlib import Path
    src_dir = Path(__file__).parent.parent
    sys.path.insert(0, str(src_dir))
    
    from core.connection_manager import VPNConnectionManager
    from core.vpn_interface import ConnectionStatus, ProtocolType, ServerInfo
    from security.input_sanitizer import InputSanitizer, SecurityException

class ConnectionWorker(QThread):
    """Worker thread for VPN operations to prevent GUI freezing"""
    
    connection_result = pyqtSignal(bool, str)
    status_update = pyqtSignal(dict)
    servers_loaded = pyqtSignal(dict)
    
    def __init__(self, manager: VPNConnectionManager):
        super().__init__()
        self.manager = manager
        self.operation = None
        self.operation_args = {}
    
    def set_operation(self, operation: str, **kwargs):
        self.operation = operation
        self.operation_args = kwargs
    
    def run(self):
        try:
            if self.operation == "connect":
                result = asyncio.run(self.manager.connect_to_provider(
                    self.operation_args['provider'],
                    self.operation_args['server'],
                    self.operation_args.get('protocol')
                ))
                self.connection_result.emit(result, "Connected" if result else "Connection failed")
            
            elif self.operation == "disconnect":
                result = asyncio.run(self.manager.disconnect())
                self.connection_result.emit(result, "Disconnected" if result else "Disconnect failed")
            
            elif self.operation == "load_servers":
                servers = asyncio.run(self.manager.get_all_servers(
                    self.operation_args.get('country')
                ))
                self.servers_loaded.emit(servers)
            
            elif self.operation == "get_status":
                status = asyncio.run(self.manager.get_connection_status())
                if status:
                    self.status_update.emit({
                        'status': status.status.value,
                        'server': status.server.name if status.server else None,
                        'ip': status.public_ip
                    })
        
        except Exception as e:
            self.connection_result.emit(False, f"Error: {str(e)}")

class ProviderConfigDialog(QDialog):
    """Dialog for configuring VPN provider credentials"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add VPN Provider")
        self.setFixedSize(400, 300)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        
        # Provider selection
        provider_layout = QHBoxLayout()
        provider_layout.addWidget(QLabel("Provider:"))
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(["NordVPN", "ExpressVPN", "Surfshark", "CyberGhost", "ProtonVPN"])
        provider_layout.addWidget(self.provider_combo)
        layout.addLayout(provider_layout)
        
        # Credentials form
        form_layout = QFormLayout()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        
        form_layout.addRow("Username:", self.username_edit)
        form_layout.addRow("Password:", self.password_edit)
        layout.addLayout(form_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("Add Provider")
        self.cancel_button = QPushButton("Cancel")
        
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
        # Connect signals
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
    
    def get_provider_info(self):
        """Get provider information with input validation"""
        try:
            # Get raw inputs
            provider = self.provider_combo.currentText().strip()
            username = self.username_edit.text().strip()
            password = self.password_edit.text()
            
            # Validate inputs using security sanitizer
            sanitized_provider = InputSanitizer.sanitize_provider_name(provider)
            sanitized_username = InputSanitizer.sanitize_username(username)
            sanitized_password = InputSanitizer.sanitize_password(password)
            
            return {
                'provider': sanitized_provider,
                'username': sanitized_username,
                'password': sanitized_password
            }
        except SecurityException as e:
            # Show user-friendly error message
            QMessageBox.critical(self, "Input Validation Error", 
                               f"Invalid input detected:\n{str(e)}\n\nPlease correct your input and try again.")
            return None
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {str(e)}")
            return None

class VPNHubMainWindow(QMainWindow):
    """Main application window for VPN Hub"""
    
    def __init__(self):
        super().__init__()
        self.manager = VPNConnectionManager()
        self.worker = ConnectionWorker(self.manager)
        self.settings = QSettings("VPNHub", "VPNHubApp")
        self.current_servers_data = {}  # Store loaded servers for filtering
        
        self.setup_ui()
        self.setup_system_tray()
        self.setup_timers()
        self.load_settings()
        
        # Connect worker signals
        self.worker.connection_result.connect(self.on_connection_result)
        self.worker.status_update.connect(self.on_status_update)
        self.worker.servers_loaded.connect(self.on_servers_loaded)
    
    def setup_ui(self):
        """Setup the main user interface"""
        self.setWindowTitle("VPN Hub - Professional Multi-Provider VPN Manager")
        self.setGeometry(100, 100, 1200, 800)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: white;
            }
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: #3c3c3c;
            }
            QTabBar::tab {
                background-color: #555;
                color: white;
                padding: 8px 16px;
                margin: 2px;
            }
            QTabBar::tab:selected {
                background-color: #007acc;
            }
            QPushButton {
                background-color: #007acc;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:pressed {
                background-color: #004578;
            }
            QPushButton:disabled {
                background-color: #555;
                color: #888;
            }
            QListWidget {
                background-color: #3c3c3c;
                color: white;
                border: 1px solid #555;
            }
            QComboBox {
                background-color: #3c3c3c;
                color: white;
                border: 1px solid #555;
                padding: 4px;
            }
        """)
        
        # Central widget with tabs
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Status bar at top
        self.setup_status_bar(layout)
        
        # Main tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Setup menu bar
        self.setup_menu_bar()
        
        # Setup tabs
        self.setup_connection_tab()
        self.setup_servers_tab()
        self.setup_providers_tab()
        self.setup_security_tab()
        self.setup_history_tab()
        self.setup_settings_tab()
    
    def setup_status_bar(self, layout):
        """Setup the status bar with connection info"""
        status_frame = QFrame()
        status_frame.setFrameStyle(QFrame.StyledPanel)
        status_frame.setMaximumHeight(80)
        
        status_layout = QHBoxLayout()
        status_frame.setLayout(status_layout)
        
        # Connection status
        self.status_label = QLabel("🔴 Disconnected")
        self.status_label.setFont(QFont("Arial", 12, QFont.Bold))
        status_layout.addWidget(self.status_label)
        
        # Current IP
        self.ip_label = QLabel("IP: Unknown")
        status_layout.addWidget(self.ip_label)
        
        # Current provider
        self.provider_label = QLabel("Provider: None")
        status_layout.addWidget(self.provider_label)
        
        status_layout.addStretch()
        
        # Quick connect/disconnect buttons
        self.quick_connect_btn = QPushButton("Quick Connect")
        self.quick_disconnect_btn = QPushButton("Disconnect")
        self.quick_disconnect_btn.setEnabled(False)
        
        # Exit button
        self.exit_btn = QPushButton("Exit")
        self.exit_btn.setStyleSheet("""
            QPushButton {
                background-color: #dc3545;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #c82333;
            }
        """)
        
        status_layout.addWidget(self.quick_connect_btn)
        status_layout.addWidget(self.quick_disconnect_btn)
        status_layout.addWidget(self.exit_btn)
        
        layout.addWidget(status_frame)
        
        # Connect buttons
        self.quick_connect_btn.clicked.connect(self.quick_connect)
        self.quick_disconnect_btn.clicked.connect(self.disconnect)
        self.exit_btn.clicked.connect(self.confirm_exit)
    
    def setup_menu_bar(self):
        """Setup the application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('&File')
        
        # Exit action
        exit_action = QAction('E&xit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.setStatusTip('Exit application')
        exit_action.triggered.connect(self.quit_application)
        file_menu.addAction(exit_action)
        
        # Separator
        file_menu.addSeparator()
        
        # Minimize to tray action
        minimize_action = QAction('&Minimize to Tray', self)
        minimize_action.setShortcut('Ctrl+M')
        minimize_action.setStatusTip('Minimize to system tray')
        minimize_action.triggered.connect(self.hide)
        file_menu.addAction(minimize_action)
        
        # View menu
        view_menu = menubar.addMenu('&View')
        
        # Show/Hide system tray
        tray_action = QAction('&Show in System Tray', self)
        tray_action.setCheckable(True)
        tray_action.setChecked(True)
        tray_action.triggered.connect(self.toggle_system_tray)
        view_menu.addAction(tray_action)
        
        # Help menu
        help_menu = menubar.addMenu('&Help')
        
        # About action
        about_action = QAction('&About VPN Hub', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def setup_connection_tab(self):
        """Setup the main connection tab"""
        connection_widget = QWidget()
        layout = QVBoxLayout()
        connection_widget.setLayout(layout)
        
        # Provider selection
        provider_layout = QHBoxLayout()
        provider_layout.addWidget(QLabel("Select Provider:"))
        
        self.provider_combo = QComboBox()
        self.provider_combo.currentTextChanged.connect(self.on_provider_changed)
        provider_layout.addWidget(self.provider_combo)
        
        provider_layout.addStretch()
        layout.addLayout(provider_layout)
        
        # Server selection
        server_layout = QHBoxLayout()
        server_layout.addWidget(QLabel("Select Server:"))
        
        self.server_combo = QComboBox()
        server_layout.addWidget(self.server_combo)
        
        self.refresh_servers_btn = QPushButton("Refresh Servers")
        self.refresh_servers_btn.clicked.connect(self.refresh_servers)
        server_layout.addWidget(self.refresh_servers_btn)
        
        layout.addLayout(server_layout)
        
        # Protocol selection
        protocol_layout = QHBoxLayout()
        protocol_layout.addWidget(QLabel("Protocol:"))
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["Auto", "OpenVPN", "WireGuard", "IKEv2"])
        protocol_layout.addWidget(self.protocol_combo)
        
        protocol_layout.addStretch()
        layout.addLayout(protocol_layout)
        
        # Connection buttons
        button_layout = QHBoxLayout()
        self.connect_btn = QPushButton("Connect")
        self.connect_btn.clicked.connect(self.connect)
        button_layout.addWidget(self.connect_btn)
        
        self.disconnect_btn = QPushButton("Disconnect")
        self.disconnect_btn.clicked.connect(self.disconnect)
        self.disconnect_btn.setEnabled(False)
        button_layout.addWidget(self.disconnect_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # Connection info display
        info_group = QGroupBox("Connection Information")
        info_layout = QGridLayout()
        info_group.setLayout(info_layout)
        
        self.info_labels = {}
        info_fields = ["Status", "Server", "Country", "Protocol", "Public IP", "Connected Since"]
        
        for i, field in enumerate(info_fields):
            label = QLabel(f"{field}:")
            value = QLabel("N/A")
            value.setStyleSheet("color: #ccc;")
            
            info_layout.addWidget(label, i, 0)
            info_layout.addWidget(value, i, 1)
            
            self.info_labels[field.lower().replace(" ", "_")] = value
        
        layout.addWidget(info_group)
        layout.addStretch()
        
        self.tab_widget.addTab(connection_widget, "Connection")
    
    def setup_servers_tab(self):
        """Setup the servers browser tab"""
        servers_widget = QWidget()
        layout = QVBoxLayout()
        servers_widget.setLayout(layout)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Country Filter:"))
        
        self.country_filter = QComboBox()
        self.country_filter.addItem("All Countries")
        self.country_filter.currentTextChanged.connect(self.filter_servers_by_country)
        filter_layout.addWidget(self.country_filter)
        
        self.load_servers_btn = QPushButton("Load Servers")
        self.load_servers_btn.clicked.connect(self.load_all_servers)
        filter_layout.addWidget(self.load_servers_btn)
        
        filter_layout.addStretch()
        layout.addLayout(filter_layout)
        
        # Servers table
        self.servers_table = QTableWidget()
        self.servers_table.setColumnCount(6)
        self.servers_table.setHorizontalHeaderLabels([
            "Provider", "Server", "Country", "City", "Load", "Features"
        ])
        
        header = self.servers_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.servers_table)
        
        self.tab_widget.addTab(servers_widget, "Servers")
    
    def setup_providers_tab(self):
        """Setup the providers management tab"""
        providers_widget = QWidget()
        layout = QVBoxLayout()
        providers_widget.setLayout(layout)
        
        # Providers list
        providers_layout = QHBoxLayout()
        
        # Left side - provider list
        left_layout = QVBoxLayout()
        left_layout.addWidget(QLabel("VPN Providers:"))
        
        self.providers_list = QListWidget()
        left_layout.addWidget(self.providers_list)
        
        # Provider management buttons
        provider_buttons = QHBoxLayout()
        self.add_provider_btn = QPushButton("Add Provider")
        self.add_provider_btn.clicked.connect(self.add_provider)
        provider_buttons.addWidget(self.add_provider_btn)
        
        self.remove_provider_btn = QPushButton("Remove Provider")
        self.remove_provider_btn.clicked.connect(self.remove_provider)
        provider_buttons.addWidget(self.remove_provider_btn)
        
        left_layout.addLayout(provider_buttons)
        
        # Right side - provider details
        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Provider Details:"))
        
        self.provider_details = QTextEdit()
        self.provider_details.setReadOnly(True)
        right_layout.addWidget(self.provider_details)
        
        # Add layouts to splitter
        splitter = QSplitter(Qt.Horizontal)
        
        left_widget = QWidget()
        left_widget.setLayout(left_layout)
        splitter.addWidget(left_widget)
        
        right_widget = QWidget()
        right_widget.setLayout(right_layout)
        splitter.addWidget(right_widget)
        
        layout.addWidget(splitter)
        
        self.tab_widget.addTab(providers_widget, "Providers")
    
    def setup_security_tab(self):
        """Setup the security settings tab"""
        security_widget = QWidget()
        layout = QVBoxLayout()
        security_widget.setLayout(layout)
        
        # Kill Switch
        kill_switch_group = QGroupBox("Kill Switch")
        kill_switch_layout = QVBoxLayout()
        
        self.kill_switch_enabled = QCheckBox("Enable Kill Switch")
        self.kill_switch_enabled.setChecked(True)
        kill_switch_layout.addWidget(self.kill_switch_enabled)
        
        kill_switch_layout.addWidget(QLabel("Automatically block internet if VPN disconnects"))
        kill_switch_group.setLayout(kill_switch_layout)
        layout.addWidget(kill_switch_group)
        
        # DNS Protection
        dns_group = QGroupBox("DNS Protection")
        dns_layout = QVBoxLayout()
        
        self.dns_protection_enabled = QCheckBox("Enable DNS Leak Protection")
        self.dns_protection_enabled.setChecked(True)
        dns_layout.addWidget(self.dns_protection_enabled)
        
        dns_layout.addWidget(QLabel("Prevent DNS queries from bypassing VPN"))
        dns_group.setLayout(dns_layout)
        layout.addWidget(dns_group)
        
        # Auto-reconnect
        reconnect_group = QGroupBox("Auto-Reconnect")
        reconnect_layout = QVBoxLayout()
        
        self.auto_reconnect_enabled = QCheckBox("Enable Auto-Reconnect")
        self.auto_reconnect_enabled.setChecked(True)
        reconnect_layout.addWidget(self.auto_reconnect_enabled)
        
        reconnect_layout.addWidget(QLabel("Automatically reconnect if connection drops"))
        reconnect_group.setLayout(reconnect_layout)
        layout.addWidget(reconnect_group)
        
        layout.addStretch()
        
        self.tab_widget.addTab(security_widget, "Security")
    
    def setup_history_tab(self):
        """Setup the connection history tab"""
        history_widget = QWidget()
        layout = QVBoxLayout()
        history_widget.setLayout(layout)
        
        layout.addWidget(QLabel("Connection History:"))
        
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(5)
        self.history_table.setHorizontalHeaderLabels([
            "Timestamp", "Provider", "Server", "Country", "Protocol"
        ])
        
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        
        layout.addWidget(self.history_table)
        
        # Clear history button
        clear_btn = QPushButton("Clear History")
        clear_btn.clicked.connect(self.clear_history)
        layout.addWidget(clear_btn)
        
        self.tab_widget.addTab(history_widget, "History")
    
    def setup_settings_tab(self):
        """Setup the application settings tab"""
        settings_widget = QWidget()
        layout = QVBoxLayout()
        settings_widget.setLayout(layout)
        
        # General settings
        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout()
        
        self.startup_connect = QCheckBox()
        general_layout.addRow("Connect on startup:", self.startup_connect)
        
        self.minimize_to_tray = QCheckBox()
        self.minimize_to_tray.setChecked(True)
        general_layout.addRow("Minimize to system tray:", self.minimize_to_tray)
        
        self.update_interval = QSpinBox()
        self.update_interval.setRange(5, 300)
        self.update_interval.setValue(30)
        self.update_interval.setSuffix(" seconds")
        general_layout.addRow("Status update interval:", self.update_interval)
        
        general_group.setLayout(general_layout)
        layout.addWidget(general_group)
        
        # Save settings button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        layout.addStretch()
        
        self.tab_widget.addTab(settings_widget, "Settings")
    
    def setup_system_tray(self):
        """Setup system tray icon"""
        # Check if system tray is available
        if not QSystemTrayIcon.isSystemTrayAvailable():
            QMessageBox.critical(self, "System Tray", 
                               "System tray is not available on this system.")
            return
        
        self.tray_icon = QSystemTrayIcon(self)
        
        # Create a simple icon programmatically if no icon file exists
        self.create_tray_icon()
        
        # Create tray menu
        tray_menu = QMenu()
        
        show_action = QAction("Show VPN Hub", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        tray_menu.addSeparator()
        
        quick_connect_action = QAction("Quick Connect", self)
        quick_connect_action.triggered.connect(self.quick_connect)
        tray_menu.addAction(quick_connect_action)
        
        disconnect_action = QAction("Disconnect", self)
        disconnect_action.triggered.connect(self.disconnect)
        tray_menu.addAction(disconnect_action)
        
        tray_menu.addSeparator()
        
        quit_action = QAction("Quit", self)
        quit_action.triggered.connect(self.quit_application)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        
        # Only show the tray icon after the icon is set
        if self.tray_icon.icon().isNull():
            print("Warning: No tray icon set, system tray will not be shown")
        else:
            self.tray_icon.show()
    
    def create_tray_icon(self):
        """Create a simple tray icon programmatically"""
        try:
            # Try to load icon from assets folder first
            import os
            assets_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'assets')
            icon_path = os.path.join(assets_path, 'vpn_hub_icon.png')
            small_icon_path = os.path.join(assets_path, 'vpn_hub_icon_small.png')
            
            # Try small icon first for system tray
            if os.path.exists(small_icon_path):
                icon = QIcon(small_icon_path)
                self.tray_icon.setIcon(icon)
                # Also set window icon
                self.setWindowIcon(icon)
                return
            elif os.path.exists(icon_path):
                icon = QIcon(icon_path)
                self.tray_icon.setIcon(icon)
                # Also set window icon
                self.setWindowIcon(icon)
                return
            
            # If no icon file exists, create a simple colored square icon
            pixmap = QPixmap(16, 16)
            pixmap.fill(QColor(0, 122, 204))  # Blue color
            
            # Draw a simple "V" for VPN
            from PyQt5.QtGui import QPainter, QPen
            painter = QPainter(pixmap)
            painter.setPen(QPen(QColor(255, 255, 255), 2))  # White pen
            
            # Draw V shape
            painter.drawLine(2, 2, 8, 12)
            painter.drawLine(8, 12, 14, 2)
            
            painter.end()
            
            icon = QIcon(pixmap)
            self.tray_icon.setIcon(icon)
            self.setWindowIcon(icon)
            
        except Exception as e:
            print(f"Warning: Could not create tray icon: {e}")
            # Create a minimal fallback icon
            pixmap = QPixmap(16, 16)
            pixmap.fill(QColor(100, 100, 100))  # Gray square
            icon = QIcon(pixmap)
            self.tray_icon.setIcon(icon)
            self.setWindowIcon(icon)
    
    def setup_timers(self):
        """Setup update timers"""
        self.status_timer = QTimer()
        self.status_timer.timeout.connect(self.update_status)
        self.status_timer.start(30000)  # Update every 30 seconds
    
    def on_provider_changed(self):
        """Handle provider selection change"""
        self.server_combo.clear()
        self.refresh_servers()
    
    def refresh_servers(self):
        """Refresh server list for selected provider"""
        provider = self.provider_combo.currentText().lower()
        if provider:
            self.worker.set_operation("load_servers")
            self.worker.start()
    
    def on_servers_loaded(self, servers_data):
        """Handle loaded servers data"""
        # Store servers data for filtering
        self.current_servers_data = servers_data
        
        # Update the dropdown for quick connect
        self.server_combo.clear()
        
        provider = self.provider_combo.currentText().lower()
        if provider in servers_data:
            for server in servers_data[provider]:
                self.server_combo.addItem(f"{server.name} ({server.country})", server)
        
        # Populate the servers table with all servers from all providers
        self.populate_servers_table(servers_data)
    
    def populate_servers_table(self, servers_data, update_filter=True):
        """Populate the servers table with server data"""
        # Clear existing data
        self.servers_table.setRowCount(0)
        
        # Get country filter
        country_filter = self.country_filter.currentText()
        
        # Collect filtered servers first
        filtered_servers = []
        for provider_name, servers in servers_data.items():
            for server in servers:
                # Apply country filter
                if country_filter != "All Countries" and server.country != country_filter:
                    continue
                filtered_servers.append((provider_name, server))
        
        # Set correct row count
        self.servers_table.setRowCount(len(filtered_servers))
        
        # Populate table with filtered servers
        for row, (provider_name, server) in enumerate(filtered_servers):
            self.servers_table.setItem(row, 0, QTableWidgetItem(provider_name.title()))
            self.servers_table.setItem(row, 1, QTableWidgetItem(server.name))
            self.servers_table.setItem(row, 2, QTableWidgetItem(server.country))
            self.servers_table.setItem(row, 3, QTableWidgetItem(server.city))
            self.servers_table.setItem(row, 4, QTableWidgetItem(f"{server.load}%"))
            self.servers_table.setItem(row, 5, QTableWidgetItem(", ".join(server.features)))
        
        # Update country filter only when loading new data
        if update_filter:
            self.update_country_filter(servers_data)
    
    def update_country_filter(self, servers_data):
        """Update country filter dropdown with available countries"""
        countries = set()
        for servers in servers_data.values():
            for server in servers:
                countries.add(server.country)
        
        # Clear and repopulate country filter
        current_country = self.country_filter.currentText()
        
        # Temporarily disconnect signal to prevent recursion
        self.country_filter.currentTextChanged.disconnect()
        
        self.country_filter.clear()
        self.country_filter.addItem("All Countries")
        
        for country in sorted(countries):
            self.country_filter.addItem(country)
        
        # Restore previous selection if it exists
        if current_country in countries:
            index = self.country_filter.findText(current_country)
            if index >= 0:
                self.country_filter.setCurrentIndex(index)
        
        # Reconnect signal
        self.country_filter.currentTextChanged.connect(self.filter_servers_by_country)
    
    def filter_servers_by_country(self):
        """Filter servers table by selected country"""
        if hasattr(self, 'current_servers_data'):
            self.populate_servers_table(self.current_servers_data, update_filter=False)
    
    def connect(self):
        """Connect to selected server"""
        provider = self.provider_combo.currentText().lower()
        server_data = self.server_combo.currentData()
        protocol_text = self.protocol_combo.currentText()
        
        if not provider or not server_data:
            QMessageBox.warning(self, "Warning", "Please select a provider and server")
            return
        
        protocol = None
        if protocol_text != "Auto":
            protocol_map = {
                "OpenVPN": ProtocolType.OPENVPN,
                "WireGuard": ProtocolType.WIREGUARD,
                "IKEv2": ProtocolType.IKEV2
            }
            protocol = protocol_map.get(protocol_text)
        
        self.connect_btn.setEnabled(False)
        self.status_label.setText("🟡 Connecting...")
        
        self.worker.set_operation("connect", provider=provider, server=server_data, protocol=protocol)
        self.worker.start()
    
    def disconnect(self):
        """Disconnect from VPN"""
        self.disconnect_btn.setEnabled(False)
        self.status_label.setText("🟡 Disconnecting...")
        
        self.worker.set_operation("disconnect")
        self.worker.start()
    
    def quick_connect(self):
        """Quick connect to best available server"""
        if self.provider_combo.count() == 0:
            QMessageBox.warning(self, "Warning", "No providers configured")
            return
        
        # Use first available provider for quick connect
        self.provider_combo.setCurrentIndex(0)
        self.refresh_servers()
        
        # Connect to first server when loaded
        if self.server_combo.count() > 0:
            self.connect()
    
    def on_connection_result(self, success, message):
        """Handle connection result"""
        if success:
            self.status_label.setText("🟢 Connected")
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(True)
            self.quick_disconnect_btn.setEnabled(True)
        else:
            self.status_label.setText("🔴 Disconnected")
            self.connect_btn.setEnabled(True)
            self.disconnect_btn.setEnabled(False)
            self.quick_disconnect_btn.setEnabled(False)
        
        QMessageBox.information(self, "Connection Status", message)
    
    def on_status_update(self, status_data):
        """Handle status update"""
        status = status_data.get('status', 'disconnected')
        server = status_data.get('server', 'None')
        ip = status_data.get('ip', 'Unknown')
        
        if status == 'connected':
            self.status_label.setText("🟢 Connected")
            self.provider_label.setText(f"Provider: {self.provider_combo.currentText()}")
            self.ip_label.setText(f"IP: {ip}")
        else:
            self.status_label.setText("🔴 Disconnected")
            self.provider_label.setText("Provider: None")
            self.ip_label.setText("IP: Unknown")
    
    def update_status(self):
        """Periodic status update"""
        if not self.worker.isRunning():
            self.worker.set_operation("get_status")
            self.worker.start()
    
    def add_provider(self):
        """Add new VPN provider with secure input validation"""
        dialog = ProviderConfigDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            provider_info = dialog.get_provider_info()
            
            # Check if input validation failed
            if provider_info is None:
                return  # Error message already shown by dialog
            
            try:
                # Add provider to manager
                success = self.manager.add_provider(provider_info['provider'], {})
                
                if success:
                    # Try to authenticate
                    auth_success = asyncio.run(self.manager.authenticate_provider(
                        provider_info['provider'],
                        provider_info['username'],
                        provider_info['password']
                    ))
                    
                    if auth_success:
                        self.update_providers_list()
                        QMessageBox.information(self, "Success", f"Added {provider_info['provider']} successfully")
                    else:
                        QMessageBox.warning(self, "Warning", "Provider added but authentication failed")
                else:
                    QMessageBox.critical(self, "Error", "Failed to add provider")
                    
            except SecurityException as e:
                QMessageBox.critical(self, "Security Error", f"Security validation failed: {str(e)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add provider: {str(e)}")
    
    def remove_provider(self):
        """Remove selected provider"""
        current_item = self.providers_list.currentItem()
        if current_item:
            provider_name = current_item.text().lower()
            success = self.manager.remove_provider(provider_name)
            
            if success:
                self.update_providers_list()
                QMessageBox.information(self, "Success", f"Removed {provider_name}")
            else:
                QMessageBox.critical(self, "Error", "Failed to remove provider")
    
    def update_providers_list(self):
        """Update the providers list"""
        self.providers_list.clear()
        self.provider_combo.clear()
        
        for provider_name in self.manager.providers.keys():
            self.providers_list.addItem(provider_name.title())
            self.provider_combo.addItem(provider_name.title())
    
    def load_all_servers(self):
        """Load servers from all providers"""
        if not self.worker.isRunning():
            self.worker.set_operation("load_servers")
            self.worker.start()
    
    def clear_history(self):
        """Clear connection history"""
        self.manager.connection_history.clear()
        self.history_table.setRowCount(0)
    
    def save_settings(self):
        """Save application settings"""
        self.settings.setValue("kill_switch", self.kill_switch_enabled.isChecked())
        self.settings.setValue("dns_protection", self.dns_protection_enabled.isChecked())
        self.settings.setValue("auto_reconnect", self.auto_reconnect_enabled.isChecked())
        self.settings.setValue("startup_connect", self.startup_connect.isChecked())
        self.settings.setValue("minimize_to_tray", self.minimize_to_tray.isChecked())
        self.settings.setValue("update_interval", self.update_interval.value())
        
        QMessageBox.information(self, "Settings", "Settings saved successfully")
    
    def load_settings(self):
        """Load application settings"""
        self.kill_switch_enabled.setChecked(self.settings.value("kill_switch", True, bool))
        self.dns_protection_enabled.setChecked(self.settings.value("dns_protection", True, bool))
        self.auto_reconnect_enabled.setChecked(self.settings.value("auto_reconnect", True, bool))
        self.startup_connect.setChecked(self.settings.value("startup_connect", False, bool))
        self.minimize_to_tray.setChecked(self.settings.value("minimize_to_tray", True, bool))
        self.update_interval.setValue(self.settings.value("update_interval", 30, int))
    
    def confirm_exit(self):
        """Confirm application exit with user"""
        reply = QMessageBox.question(
            self, 'Exit VPN Hub', 
            'Are you sure you want to exit VPN Hub?\n\nThis will disconnect any active VPN connections.',
            QMessageBox.Yes | QMessageBox.No, 
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.quit_application()
    
    def toggle_system_tray(self, checked):
        """Toggle system tray visibility"""
        if checked:
            if not hasattr(self, 'tray_icon') or not self.tray_icon.isVisible():
                self.setup_system_tray()
        else:
            if hasattr(self, 'tray_icon') and self.tray_icon.isVisible():
                self.tray_icon.hide()
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>VPN Hub</h2>
        <p><b>Version:</b> 1.0.0</p>
        <p><b>Professional Multi-Provider VPN Manager</b></p>
        <p>Enterprise-grade secure VPN management with comprehensive protection.</p>
        
        <h3>Features:</h3>
        <ul>
        <li>Multi-provider support (NordVPN, ExpressVPN, Surfshark, CyberGhost, ProtonVPN)</li>
        <li>Advanced security features (Kill switch, DNS protection)</li>
        <li>Real-time security monitoring</li>
        <li>Secure credential storage</li>
        <li>Connection monitoring and analytics</li>
        </ul>
        
        <p><b>Security Status:</b> <span style="color: green;">FULLY HARDENED</span></p>
        <p><small>© 2025 FNBubbles420 Org</small></p>
        """
        
        QMessageBox.about(self, "About VPN Hub", about_text)
    
    def closeEvent(self, event):
        """Handle window close event"""
        # Check if minimize to tray is enabled and tray is available
        if (hasattr(self, 'minimize_to_tray') and 
            self.minimize_to_tray.isChecked() and 
            hasattr(self, 'tray_icon') and 
            self.tray_icon.isVisible()):
            
            # Hide window to tray instead of closing
            self.hide()
            if not hasattr(self, '_tray_message_shown'):
                self.tray_icon.showMessage(
                    "VPN Hub",
                    "Application was minimized to tray",
                    QSystemTrayIcon.Information,
                    2000
                )
                self._tray_message_shown = True
            event.ignore()
        else:
            # Ask for confirmation before closing
            reply = QMessageBox.question(
                self, 'Close VPN Hub', 
                'Do you want to exit VPN Hub or minimize to system tray?\n\nNote: Exiting will disconnect any active VPN connections.',
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel, 
                QMessageBox.Cancel
            )
            
            if reply == QMessageBox.Yes:
                # User wants to exit
                self.quit_application()
                event.accept()
            elif reply == QMessageBox.No:
                # User wants to minimize to tray
                if hasattr(self, 'tray_icon') and self.tray_icon.isVisible():
                    self.hide()
                    event.ignore()
                else:
                    # No tray available, just minimize normally
                    self.showMinimized()
                    event.ignore()
            else:
                # User cancelled
                event.ignore()
    
    def quit_application(self):
        """Quit the application"""
        # Disconnect if connected
        if self.manager.active_provider:
            asyncio.run(self.manager.disconnect())
        
        QApplication.quit()

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Allow application to quit when last window is closed (but we'll handle it in closeEvent)
    app.setQuitOnLastWindowClosed(True)
    
    # Set application properties
    app.setApplicationName("VPN Hub")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("FNBubbles420 Org")
    
    # Create and show main window
    window = VPNHubMainWindow()
    window.show()
    
    return app.exec_()

if __name__ == "__main__":
    main()
