#!/usr/bin/env python3
"""
Logger Module
Handles logging functionality for the NetToolbox application

Author: NetTools Team
"""

import os
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional


class Logger:
    """Enhanced logging functionality for NetToolbox."""
    
    def __init__(self, log_dir: str = "logs"):
        """
        Initialize the logger.
        
        Args:
            log_dir: Directory to store log files
        """
        self.log_dir = log_dir
        self.ensure_log_dir()
        self.setup_logging()
    
    def ensure_log_dir(self):
        """Ensure log directory exists."""
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
    
    def setup_logging(self):
        """Setup logging configuration."""
        # Create timestamp for log file
        timestamp = datetime.now().strftime("%Y%m%d")
        log_file = os.path.join(self.log_dir, f"nettools_{timestamp}.log")
        
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('NetToolbox')
        self.logger.info("NetToolbox logging initialized")
    
    def log_action(self, action: str, details: Optional[Dict] = None, 
                   level: str = "INFO"):
        """
        Log an action with optional details.
        
        Args:
            action: Description of the action
            details: Additional details dictionary
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details or {}
        }
        
        # Log to file
        if level.upper() == "DEBUG":
            self.logger.debug(f"{action} - {details}")
        elif level.upper() == "WARNING":
            self.logger.warning(f"{action} - {details}")
        elif level.upper() == "ERROR":
            self.logger.error(f"{action} - {details}")
        elif level.upper() == "CRITICAL":
            self.logger.critical(f"{action} - {details}")
        else:
            self.logger.info(f"{action} - {details}")
        
        # Also save to JSON log for structured data
        self.save_json_log(log_entry)
    
    def save_json_log(self, log_entry: Dict[str, Any]):
        """Save log entry as JSON."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d")
            json_log_file = os.path.join(self.log_dir, f"nettools_{timestamp}.json")
            
            # Read existing entries
            entries = []
            if os.path.exists(json_log_file):
                try:
                    with open(json_log_file, 'r') as f:
                        entries = json.load(f)
                except (json.JSONDecodeError, FileNotFoundError):
                    entries = []
            
            # Add new entry
            entries.append(log_entry)
            
            # Write back to file
            with open(json_log_file, 'w') as f:
                json.dump(entries, f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Failed to save JSON log: {str(e)}")
    
    def log_scan_start(self, scan_type: str, target: str, options: Dict = None):
        """Log the start of a scan."""
        self.log_action(
            f"Scan Started: {scan_type}",
            {
                "scan_type": scan_type,
                "target": target,
                "options": options or {}
            }
        )
    
    def log_scan_complete(self, scan_type: str, target: str, results_count: int, 
                         duration: float):
        """Log scan completion."""
        self.log_action(
            f"Scan Completed: {scan_type}",
            {
                "scan_type": scan_type,
                "target": target,
                "results_count": results_count,
                "duration_seconds": duration
            }
        )
    
    def log_error(self, error_msg: str, exception: Exception = None):
        """Log an error."""
        details = {"error_message": error_msg}
        if exception:
            details["exception_type"] = type(exception).__name__
            details["exception_details"] = str(exception)
        
        self.log_action("Error occurred", details, "ERROR")
    
    def log_security_event(self, event_type: str, target: str, details: Dict):
        """Log security-related events."""
        self.log_action(
            f"Security Event: {event_type}",
            {
                "event_type": event_type,
                "target": target,
                "security_details": details
            },
            "WARNING"
        )
    
    def get_recent_logs(self, count: int = 10) -> list:
        """
        Get recent log entries.
        
        Args:
            count: Number of recent entries to return
            
        Returns:
            List of recent log entries
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d")
            json_log_file = os.path.join(self.log_dir, f"nettools_{timestamp}.json")
            
            if os.path.exists(json_log_file):
                with open(json_log_file, 'r') as f:
                    entries = json.load(f)
                    return entries[-count:] if len(entries) > count else entries
        except Exception:
            pass
        
        return []
    
    def clear_old_logs(self, days_to_keep: int = 30):
        """
        Clear old log files.
        
        Args:
            days_to_keep: Number of days of logs to keep
        """
        try:
            current_time = datetime.now()
            
            for filename in os.listdir(self.log_dir):
                file_path = os.path.join(self.log_dir, filename)
                
                if os.path.isfile(file_path):
                    file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                    age_days = (current_time - file_time).days
                    
                    if age_days > days_to_keep:
                        os.remove(file_path)
                        self.log_action(f"Removed old log file: {filename}")
                        
        except Exception as e:
            self.log_error(f"Failed to clear old logs: {str(e)}")