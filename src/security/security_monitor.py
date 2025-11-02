"""
Security Monitoring and Auditing Module

This module provides:
1. Security event logging
2. Anomaly detection
3. Failed authentication tracking
4. Security metrics and reporting
"""

import logging
import json
import time
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from collections import defaultdict, deque
from enum import Enum
import os
import sys
from dataclasses import dataclass, asdict

from .input_sanitizer import SecurityException

class SecurityEventType(Enum):
    """Types of security events"""
    AUTHENTICATION_SUCCESS = "auth_success"
    AUTHENTICATION_FAILURE = "auth_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    COMMAND_INJECTION_ATTEMPT = "command_injection_attempt"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    NETWORK_ANOMALY = "network_anomaly"
    FILE_INTEGRITY_VIOLATION = "file_integrity_violation"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SYSTEM_MODIFICATION = "system_modification"

class SecuritySeverity(Enum):
    """Security event severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_type: SecurityEventType
    severity: SecuritySeverity
    timestamp: float
    source: str
    message: str
    details: Dict[str, Any]
    user_context: Optional[str] = None
    ip_address: Optional[str] = None
    process_id: Optional[int] = None
    session_id: Optional[str] = None

class SecurityMonitor:
    """Comprehensive security monitoring and auditing system"""
    
    def __init__(self, log_directory: Optional[str] = None):
        """
        Initialize security monitor
        
        Args:
            log_directory: Directory for security logs (defaults to ~/.vpnhub/security_logs)
        """
        # Setup logging
        self.logger = logging.getLogger(__name__)
        
        # Configure log directory
        if log_directory:
            self.log_directory = Path(log_directory)
        else:
            home_dir = Path.home()
            self.log_directory = home_dir / '.vpnhub' / 'security_logs'
            
        self.log_directory.mkdir(parents=True, exist_ok=True)
        
        # Secure log file permissions
        if sys.platform != "win32":
            os.chmod(self.log_directory, 0o700)
            
        # Initialize log files
        self.security_log_file = self.log_directory / 'security_events.jsonl'
        self.audit_log_file = self.log_directory / 'audit_trail.jsonl'
        self.metrics_file = self.log_directory / 'security_metrics.json'
        
        # Initialize monitoring components
        self._setup_security_logger()
        self._init_anomaly_detector()
        self._init_authentication_tracker()
        self._init_metrics_collector()
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Event queue for real-time processing
        self.event_queue = deque(maxlen=1000)
        
        # Start background monitoring
        self._start_background_monitoring()
        
    def _setup_security_logger(self) -> None:
        """Setup dedicated security event logger"""
        try:
            # Create security logger
            self.security_logger = logging.getLogger('vpnhub.security')
            self.security_logger.setLevel(logging.INFO)
            
            # Create file handler with rotation
            from logging.handlers import RotatingFileHandler
            handler = RotatingFileHandler(
                self.security_log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            
            # Create secure formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(name)s - %(message)s'
            )
            handler.setFormatter(formatter)
            
            self.security_logger.addHandler(handler)
            
            # Set secure file permissions
            if sys.platform != "win32":
                os.chmod(self.security_log_file, 0o600)
                
        except Exception as e:
            self.logger.error(f"Failed to setup security logger: {e}")
            
    def _init_anomaly_detector(self) -> None:
        """Initialize anomaly detection system"""
        self.anomaly_detector = {
            'failed_auth_threshold': 5,  # Failed attempts per time window
            'failed_auth_window': 300,   # 5 minutes
            'command_frequency_threshold': 10,  # Commands per minute
            'privilege_escalation_threshold': 3,  # Escalations per hour
            'network_request_threshold': 100,  # Requests per minute
            'unusual_activity_patterns': []
        }
        
        # Tracking data structures
        self.failed_authentications = defaultdict(list)
        self.command_frequencies = defaultdict(list)
        self.privilege_escalations = defaultdict(list)
        self.network_requests = defaultdict(list)
        
    def _init_authentication_tracker(self) -> None:
        """Initialize authentication tracking"""
        self.auth_tracker = {
            'failed_attempts': defaultdict(int),
            'successful_logins': defaultdict(list),
            'blocked_users': set(),
            'suspicious_patterns': []
        }
        
    def _init_metrics_collector(self) -> None:
        """Initialize security metrics collection"""
        self.metrics = {
            'events_by_type': defaultdict(int),
            'events_by_severity': defaultdict(int),
            'authentication_stats': {
                'total_attempts': 0,
                'successful_attempts': 0,
                'failed_attempts': 0,
                'blocked_attempts': 0
            },
            'anomaly_stats': {
                'total_anomalies': 0,
                'resolved_anomalies': 0,
                'active_anomalies': 0
            },
            'system_stats': {
                'uptime': time.time(),
                'monitored_processes': 0,
                'active_sessions': 0
            }
        }
        
    def _start_background_monitoring(self) -> None:
        """Start background monitoring thread"""
        try:
            self.monitoring_thread = threading.Thread(
                target=self._background_monitor,
                daemon=True
            )
            self.monitoring_thread.start()
            self.logger.info("Background security monitoring started")
        except Exception as e:
            self.logger.error(f"Failed to start background monitoring: {e}")
            
    def _background_monitor(self) -> None:
        """Background monitoring loop"""
        while True:
            try:
                # Process event queue
                self._process_event_queue()
                
                # Check for anomalies
                self._check_anomalies()
                
                # Update metrics
                self._update_metrics()
                
                # Cleanup old data
                self._cleanup_old_data()
                
                # Sleep for 60 seconds
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Background monitoring error: {e}")
                time.sleep(60)
                
    def log_security_event(self, 
                          event_type: SecurityEventType,
                          severity: SecuritySeverity,
                          source: str,
                          message: str,
                          details: Optional[Dict[str, Any]] = None,
                          user_context: Optional[str] = None) -> None:
        """Log a security event"""
        try:
            with self._lock:
                # Create security event
                event = SecurityEvent(
                    event_type=event_type,
                    severity=severity,
                    timestamp=time.time(),
                    source=source,
                    message=message,
                    details=details or {},
                    user_context=user_context,
                    process_id=os.getpid(),
                    session_id=self._get_session_id()
                )
                
                # Add to event queue
                self.event_queue.append(event)
                
                # Log to security logger
                log_level = self._severity_to_log_level(severity)
                event_data = asdict(event)
                event_data['event_type'] = event_type.value
                event_data['severity'] = severity.value
                
                self.security_logger.log(
                    log_level,
                    f"SECURITY_EVENT: {message}",
                    extra={'security_event': event_data}
                )
                
                # Write to security log file
                self._write_security_event(event)
                
                # Update metrics
                self.metrics['events_by_type'][event_type.value] += 1
                self.metrics['events_by_severity'][severity.value] += 1
                
                # Check for immediate threats
                if severity == SecuritySeverity.CRITICAL:
                    self._handle_critical_event(event)
                    
        except Exception as e:
            self.logger.error(f"Failed to log security event: {e}")
            
    def log_authentication_attempt(self, 
                                  username: str,
                                  provider: str,
                                  success: bool,
                                  ip_address: Optional[str] = None,
                                  details: Optional[Dict[str, Any]] = None) -> None:
        """Log authentication attempt"""
        try:
            with self._lock:
                current_time = time.time()
                
                if success:
                    # Log successful authentication
                    self.log_security_event(
                        SecurityEventType.AUTHENTICATION_SUCCESS,
                        SecuritySeverity.LOW,
                        f"{provider}_provider",
                        f"Successful authentication for user {username}",
                        details,
                        username
                    )
                    
                    # Update tracking
                    self.auth_tracker['successful_logins'][username].append(current_time)
                    self.metrics['authentication_stats']['successful_attempts'] += 1
                    
                    # Clear failed attempts for this user
                    if username in self.failed_authentications:
                        del self.failed_authentications[username]
                        
                else:
                    # Log failed authentication
                    self.log_security_event(
                        SecurityEventType.AUTHENTICATION_FAILURE,
                        SecuritySeverity.MEDIUM,
                        f"{provider}_provider",
                        f"Failed authentication for user {username}",
                        details,
                        username
                    )
                    
                    # Track failed attempts
                    self.failed_authentications[username].append(current_time)
                    self.auth_tracker['failed_attempts'][username] += 1
                    self.metrics['authentication_stats']['failed_attempts'] += 1
                    
                    # Check for brute force attack
                    self._check_brute_force_attack(username, ip_address)
                    
                self.metrics['authentication_stats']['total_attempts'] += 1
                
        except Exception as e:
            self.logger.error(f"Failed to log authentication attempt: {e}")
            
    def log_command_execution(self, 
                             command: List[str],
                             user_context: str,
                             success: bool,
                             output: Optional[str] = None) -> None:
        """Log command execution"""
        try:
            with self._lock:
                # Sanitize command for logging (remove sensitive data)
                safe_command = self._sanitize_command_for_logging(command)
                
                severity = SecuritySeverity.LOW if success else SecuritySeverity.MEDIUM
                event_type = SecurityEventType.SYSTEM_MODIFICATION if success else SecurityEventType.SUSPICIOUS_ACTIVITY
                
                details = {
                    'command': safe_command,
                    'success': success,
                    'output_length': len(output) if output else 0
                }
                
                self.log_security_event(
                    event_type,
                    severity,
                    'command_executor',
                    f"Command execution: {' '.join(safe_command[:3])}{'...' if len(safe_command) > 3 else ''}",
                    details,
                    user_context
                )
                
                # Track command frequency
                current_time = time.time()
                self.command_frequencies[user_context].append(current_time)
                
        except Exception as e:
            self.logger.error(f"Failed to log command execution: {e}")
            
    def log_privilege_escalation(self, 
                                operation: str,
                                user_context: str,
                                granted: bool,
                                reason: str) -> None:
        """Log privilege escalation attempt"""
        try:
            with self._lock:
                severity = SecuritySeverity.HIGH if granted else SecuritySeverity.MEDIUM
                
                details = {
                    'operation': operation,
                    'granted': granted,
                    'reason': reason
                }
                
                self.log_security_event(
                    SecurityEventType.PRIVILEGE_ESCALATION,
                    severity,
                    'privilege_manager',
                    f"Privilege escalation {'granted' if granted else 'denied'} for {operation}",
                    details,
                    user_context
                )
                
                # Track escalation attempts
                current_time = time.time()
                self.privilege_escalations[user_context].append({
                    'timestamp': current_time,
                    'operation': operation,
                    'granted': granted
                })
                
        except Exception as e:
            self.logger.error(f"Failed to log privilege escalation: {e}")
            
    def log_network_activity(self, 
                            url: str,
                            method: str,
                            status_code: Optional[int] = None,
                            user_context: Optional[str] = None) -> None:
        """Log network activity"""
        try:
            with self._lock:
                # Sanitize URL for logging
                safe_url = self._sanitize_url_for_logging(url)
                
                severity = SecuritySeverity.LOW
                if status_code and status_code >= 400:
                    severity = SecuritySeverity.MEDIUM
                    
                details = {
                    'url': safe_url,
                    'method': method,
                    'status_code': status_code
                }
                
                self.log_security_event(
                    SecurityEventType.NETWORK_ANOMALY if status_code and status_code >= 400 else SecurityEventType.SUSPICIOUS_ACTIVITY,
                    severity,
                    'network_security',
                    f"Network request: {method} {safe_url}",
                    details,
                    user_context
                )
                
                # Track network request frequency
                current_time = time.time()
                self.network_requests[user_context or 'anonymous'].append(current_time)
                
        except Exception as e:
            self.logger.error(f"Failed to log network activity: {e}")
            
    def _check_anomalies(self) -> None:
        """Check for security anomalies"""
        try:
            current_time = time.time()
            
            # Check failed authentication anomalies
            self._check_failed_auth_anomalies(current_time)
            
            # Check command frequency anomalies
            self._check_command_frequency_anomalies(current_time)
            
            # Check privilege escalation anomalies
            self._check_privilege_escalation_anomalies(current_time)
            
            # Check network request anomalies
            self._check_network_anomalies(current_time)
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            
    def _check_failed_auth_anomalies(self, current_time: float) -> None:
        """Check for failed authentication anomalies"""
        window_start = current_time - self.anomaly_detector['failed_auth_window']
        
        for username, attempts in self.failed_authentications.items():
            # Remove old attempts
            recent_attempts = [t for t in attempts if t > window_start]
            self.failed_authentications[username] = recent_attempts
            
            # Check threshold
            if len(recent_attempts) >= self.anomaly_detector['failed_auth_threshold']:
                self.log_security_event(
                    SecurityEventType.SUSPICIOUS_ACTIVITY,
                    SecuritySeverity.HIGH,
                    'anomaly_detector',
                    f"Brute force attack detected for user {username}",
                    {
                        'failed_attempts': len(recent_attempts),
                        'time_window': self.anomaly_detector['failed_auth_window']
                    },
                    username
                )
                
    def _check_command_frequency_anomalies(self, current_time: float) -> None:
        """Check for command frequency anomalies"""
        window_start = current_time - 60  # 1 minute window
        
        for user, commands in self.command_frequencies.items():
            # Remove old commands
            recent_commands = [t for t in commands if t > window_start]
            self.command_frequencies[user] = recent_commands
            
            # Check threshold
            if len(recent_commands) >= self.anomaly_detector['command_frequency_threshold']:
                self.log_security_event(
                    SecurityEventType.SUSPICIOUS_ACTIVITY,
                    SecuritySeverity.MEDIUM,
                    'anomaly_detector',
                    f"High command frequency detected for user {user}",
                    {
                        'commands_per_minute': len(recent_commands),
                        'threshold': self.anomaly_detector['command_frequency_threshold']
                    },
                    user
                )
                
    def _check_privilege_escalation_anomalies(self, current_time: float) -> None:
        """Check for privilege escalation anomalies"""
        window_start = current_time - 3600  # 1 hour window
        
        for user, escalations in self.privilege_escalations.items():
            # Remove old escalations
            recent_escalations = [e for e in escalations if e['timestamp'] > window_start]
            self.privilege_escalations[user] = recent_escalations
            
            # Check threshold
            if len(recent_escalations) >= self.anomaly_detector['privilege_escalation_threshold']:
                self.log_security_event(
                    SecurityEventType.SUSPICIOUS_ACTIVITY,
                    SecuritySeverity.HIGH,
                    'anomaly_detector',
                    f"Excessive privilege escalation attempts for user {user}",
                    {
                        'escalations_per_hour': len(recent_escalations),
                        'threshold': self.anomaly_detector['privilege_escalation_threshold']
                    },
                    user
                )
                
    def _check_network_anomalies(self, current_time: float) -> None:
        """Check for network anomalies"""
        window_start = current_time - 60  # 1 minute window
        
        for user, requests in self.network_requests.items():
            # Remove old requests
            recent_requests = [t for t in requests if t > window_start]
            self.network_requests[user] = recent_requests
            
            # Check threshold
            if len(recent_requests) >= self.anomaly_detector['network_request_threshold']:
                self.log_security_event(
                    SecurityEventType.NETWORK_ANOMALY,
                    SecuritySeverity.MEDIUM,
                    'anomaly_detector',
                    f"High network request frequency for user {user}",
                    {
                        'requests_per_minute': len(recent_requests),
                        'threshold': self.anomaly_detector['network_request_threshold']
                    },
                    user
                )
                
    def _check_brute_force_attack(self, username: str, ip_address: Optional[str]) -> None:
        """Check for brute force attack"""
        try:
            current_time = time.time()
            window_start = current_time - self.anomaly_detector['failed_auth_window']
            
            # Get recent failed attempts
            recent_attempts = [
                t for t in self.failed_authentications[username] 
                if t > window_start
            ]
            
            if len(recent_attempts) >= self.anomaly_detector['failed_auth_threshold']:
                # Block user temporarily
                self.auth_tracker['blocked_users'].add(username)
                
                self.log_security_event(
                    SecurityEventType.SUSPICIOUS_ACTIVITY,
                    SecuritySeverity.CRITICAL,
                    'brute_force_detector',
                    f"Brute force attack detected - user {username} temporarily blocked",
                    {
                        'failed_attempts': len(recent_attempts),
                        'ip_address': ip_address,
                        'action': 'user_blocked'
                    },
                    username
                )
                
        except Exception as e:
            self.logger.error(f"Brute force check failed: {e}")
            
    def _sanitize_command_for_logging(self, command: List[str]) -> List[str]:
        """Sanitize command for safe logging"""
        try:
            safe_command = []
            for arg in command:
                # Replace potential passwords/credentials
                if any(keyword in arg.lower() for keyword in ['password', 'passwd', 'key', 'token', 'secret']):
                    safe_command.append('[REDACTED]')
                else:
                    safe_command.append(arg)
            return safe_command
        except:
            return ['[COMMAND_SANITIZATION_FAILED]']
            
    def _sanitize_url_for_logging(self, url: str) -> str:
        """Sanitize URL for safe logging"""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            
            # Remove sensitive query parameters
            sensitive_params = ['password', 'token', 'key', 'secret', 'auth', 'api_key']
            if parsed.query:
                query_params = parse_qs(parsed.query)
                for param in sensitive_params:
                    if param in query_params:
                        query_params[param] = ['[REDACTED]']
                        
                # Reconstruct URL
                from urllib.parse import urlencode
                safe_query = urlencode(query_params, doseq=True)
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{safe_query}"
                
            return url
        except:
            return '[URL_SANITIZATION_FAILED]'
            
    def _write_security_event(self, event: SecurityEvent) -> None:
        """Write security event to log file"""
        try:
            event_data = asdict(event)
            event_data['event_type'] = event.event_type.value
            event_data['severity'] = event.severity.value
            
            with open(self.security_log_file, 'a') as f:
                f.write(json.dumps(event_data) + '\n')
                
        except Exception as e:
            self.logger.error(f"Failed to write security event: {e}")
            
    def _severity_to_log_level(self, severity: SecuritySeverity) -> int:
        """Convert security severity to logging level"""
        mapping = {
            SecuritySeverity.LOW: logging.INFO,
            SecuritySeverity.MEDIUM: logging.WARNING,
            SecuritySeverity.HIGH: logging.ERROR,
            SecuritySeverity.CRITICAL: logging.CRITICAL
        }
        return mapping.get(severity, logging.INFO)
        
    def _get_session_id(self) -> str:
        """Get current session ID"""
        try:
            # Generate session ID based on process and time
            session_data = f"{os.getpid()}{time.time()}"
            return hashlib.md5(session_data.encode()).hexdigest()[:16]
        except:
            return "unknown"
            
    def _handle_critical_event(self, event: SecurityEvent) -> None:
        """Handle critical security events"""
        try:
            # Log to system log
            self.logger.critical(f"CRITICAL SECURITY EVENT: {event.message}")
            
            # Could implement additional actions:
            # - Send alerts
            # - Block suspicious IPs
            # - Trigger automatic responses
            
        except Exception as e:
            self.logger.error(f"Critical event handling failed: {e}")
            
    def _process_event_queue(self) -> None:
        """Process events in the queue"""
        try:
            while self.event_queue:
                event = self.event_queue.popleft()
                # Additional real-time processing could go here
                
        except Exception as e:
            self.logger.error(f"Event queue processing failed: {e}")
            
    def _update_metrics(self) -> None:
        """Update security metrics"""
        try:
            self.metrics['system_stats']['uptime'] = time.time() - self.metrics['system_stats']['uptime']
            
            # Save metrics to file
            with open(self.metrics_file, 'w') as f:
                json.dump(self.metrics, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Metrics update failed: {e}")
            
    def _cleanup_old_data(self) -> None:
        """Clean up old tracking data"""
        try:
            current_time = time.time()
            cutoff_time = current_time - 86400  # 24 hours
            
            # Clean up old failed authentications
            for username in list(self.failed_authentications.keys()):
                self.failed_authentications[username] = [
                    t for t in self.failed_authentications[username] 
                    if t > cutoff_time
                ]
                if not self.failed_authentications[username]:
                    del self.failed_authentications[username]
                    
            # Clean up other tracking data structures similarly
            # ... (similar cleanup for other data structures)
            
        except Exception as e:
            self.logger.error(f"Data cleanup failed: {e}")
            
    def get_security_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        try:
            cutoff_time = time.time() - (hours * 3600)
            
            # Read security events from log file
            events = []
            if self.security_log_file.exists():
                with open(self.security_log_file, 'r') as f:
                    for line in f:
                        try:
                            event_data = json.loads(line)
                            if event_data['timestamp'] > cutoff_time:
                                events.append(event_data)
                        except:
                            continue
                            
            # Generate report
            report = {
                'report_period_hours': hours,
                'report_generated': datetime.now().isoformat(),
                'total_events': len(events),
                'events_by_type': defaultdict(int),
                'events_by_severity': defaultdict(int),
                'top_users': defaultdict(int),
                'authentication_summary': {
                    'successful': 0,
                    'failed': 0,
                    'blocked': len(self.auth_tracker['blocked_users'])
                },
                'anomalies_detected': 0,
                'critical_events': []
            }
            
            # Process events
            for event in events:
                event_type = event.get('event_type', 'unknown')
                severity = event.get('severity', 1)
                user = event.get('user_context', 'anonymous')
                
                report['events_by_type'][event_type] += 1
                report['events_by_severity'][severity] += 1
                report['top_users'][user] += 1
                
                if event_type == 'auth_success':
                    report['authentication_summary']['successful'] += 1
                elif event_type == 'auth_failure':
                    report['authentication_summary']['failed'] += 1
                    
                if severity == 4:  # Critical
                    report['critical_events'].append(event)
                    
                if 'anomaly' in event.get('source', '').lower():
                    report['anomalies_detected'] += 1
                    
            # Convert defaultdicts to regular dicts
            report['events_by_type'] = dict(report['events_by_type'])
            report['events_by_severity'] = dict(report['events_by_severity'])
            report['top_users'] = dict(report['top_users'])
            
            return report
            
        except Exception as e:
            self.logger.error(f"Security report generation failed: {e}")
            return {'error': str(e)}

# Global instance
_security_monitor = None

def get_security_monitor() -> SecurityMonitor:
    """Get global security monitor instance"""
    global _security_monitor
    if _security_monitor is None:
        _security_monitor = SecurityMonitor()
    return _security_monitor