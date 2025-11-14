#!/usr/bin/env python3
"""
Monitoring Tools Module
Handles network monitoring, uptime checks, and alerting

Author: NetTools Team
"""

import time
import threading
import subprocess
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Callable
import json
import os
import socket

class MonitoringTools:
    """Network monitoring and alerting functionality."""
    
    def __init__(self):
        """Initialize monitoring tools."""
        self.active_monitors = {}
        self.monitoring_active = False
        self.monitor_threads = {}
        self.alert_callbacks = []
        self.monitoring_data = {}
        self.data_file = "monitoring_data.json"
        
        # Load existing monitoring data
        self.load_monitoring_data()
    
    def load_monitoring_data(self):
        """Load monitoring data from file."""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as f:
                    self.monitoring_data = json.load(f)
        except Exception:
            self.monitoring_data = {}
    
    def save_monitoring_data(self):
        """Save monitoring data to file."""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(self.monitoring_data, f, indent=2, default=str)
        except Exception:
            pass
    
    def add_host_monitor(self, host: str, interval: int = 60, 
                        monitor_type: str = "ping") -> bool:
        """
        Add host monitoring.
        
        Args:
            host: Host to monitor
            interval: Check interval in seconds
            monitor_type: Type of monitoring (ping, http, tcp)
            
        Returns:
            True if monitor added successfully
        """
        monitor_id = f"{host}_{monitor_type}"
        
        if monitor_id in self.active_monitors:
            return False
        
        monitor_config = {
            'host': host,
            'type': monitor_type,
            'interval': interval,
            'active': True,
            'last_check': None,
            'status': 'Unknown',
            'consecutive_failures': 0,
            'total_checks': 0,
            'successful_checks': 0
        }
        
        self.active_monitors[monitor_id] = monitor_config
        
        # Initialize monitoring data
        if monitor_id not in self.monitoring_data:
            self.monitoring_data[monitor_id] = {
                'history': [],
                'stats': {
                    'uptime_percentage': 0,
                    'average_response_time': 0,
                    'last_downtime': None,
                    'total_downtime': 0
                }
            }
        
        # Start monitoring thread
        thread = threading.Thread(
            target=self._monitor_worker,
            args=(monitor_id, monitor_config)
        )
        thread.daemon = True
        thread.start()
        
        self.monitor_threads[monitor_id] = thread
        self.monitoring_active = True
        
        return True
    
    def remove_host_monitor(self, host: str, monitor_type: str = "ping") -> bool:
        """Remove host monitoring."""
        monitor_id = f"{host}_{monitor_type}"
        
        if monitor_id in self.active_monitors:
            self.active_monitors[monitor_id]['active'] = False
            del self.active_monitors[monitor_id]
            
            if monitor_id in self.monitor_threads:
                del self.monitor_threads[monitor_id]
            
            return True
        
        return False
    
    def _monitor_worker(self, monitor_id: str, config: Dict):
        """Worker thread for monitoring."""
        while config.get('active', False) and self.monitoring_active:
            try:
                start_time = time.time()
                
                # Perform check based on monitor type
                if config['type'] == 'ping':
                    success, response_time, details = self._ping_check(config['host'])
                elif config['type'] == 'http':
                    success, response_time, details = self._http_check(config['host'])
                elif config['type'] == 'tcp':
                    success, response_time, details = self._tcp_check(config['host'])
                else:
                    success, response_time, details = False, 0, "Unknown monitor type"
                
                # Update monitor status
                config['last_check'] = datetime.now()
                config['total_checks'] += 1
                
                if success:
                    config['status'] = 'Up'
                    config['consecutive_failures'] = 0
                    config['successful_checks'] += 1
                else:
                    config['status'] = 'Down'
                    config['consecutive_failures'] += 1
                
                # Record monitoring data
                self._record_monitoring_data(monitor_id, success, response_time, details)
                
                # Check for alerts
                self._check_alerts(monitor_id, config, success)
                
                # Sleep until next check
                time.sleep(config['interval'])
                
            except Exception:
                time.sleep(config['interval'])
    
    def _ping_check(self, host: str) -> tuple:
        """Perform ping check."""
        try:
            start_time = time.time()
            
            if subprocess.os.name == 'nt':  # Windows
                cmd = f'ping -n 1 -w 3000 {host}'
            else:  # Unix/Linux
                cmd = f'ping -c 1 -W 3 {host}'
            
            result = subprocess.run(cmd.split(), capture_output=True, 
                                  text=True, timeout=10)
            
            response_time = (time.time() - start_time) * 1000
            
            if result.returncode == 0:
                return True, response_time, "Ping successful"
            else:
                return False, response_time, "Ping failed"
                
        except Exception as e:
            return False, 0, f"Ping error: {str(e)}"
    
    def _http_check(self, url: str) -> tuple:
        """Perform HTTP check."""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
            
            start_time = time.time()
            response = requests.get(url, timeout=10, verify=False)
            response_time = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                return True, response_time, f"HTTP 200 OK"
            else:
                return False, response_time, f"HTTP {response.status_code}"
                
        except Exception as e:
            return False, 0, f"HTTP error: {str(e)}"
    
    def _tcp_check(self, host_port: str) -> tuple:
        """Perform TCP port check."""
        try:
            if ':' in host_port:
                host, port = host_port.rsplit(':', 1)
                port = int(port)
            else:
                host = host_port
                port = 80
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            response_time = (time.time() - start_time) * 1000
            
            if result == 0:
                return True, response_time, f"TCP port {port} open"
            else:
                return False, response_time, f"TCP port {port} closed"
                
        except Exception as e:
            return False, 0, f"TCP error: {str(e)}"
    
    def _record_monitoring_data(self, monitor_id: str, success: bool, 
                               response_time: float, details: str):
        """Record monitoring data point."""
        timestamp = datetime.now().isoformat()
        
        data_point = {
            'timestamp': timestamp,
            'success': success,
            'response_time': response_time,
            'details': details
        }
        
        if monitor_id not in self.monitoring_data:
            self.monitoring_data[monitor_id] = {'history': [], 'stats': {}}
        
        # Add to history
        self.monitoring_data[monitor_id]['history'].append(data_point)
        
        # Limit history size
        if len(self.monitoring_data[monitor_id]['history']) > 1000:
            self.monitoring_data[monitor_id]['history'] = \
                self.monitoring_data[monitor_id]['history'][-500:]
        
        # Update statistics
        self._update_statistics(monitor_id)
        
        # Save data periodically
        if len(self.monitoring_data[monitor_id]['history']) % 10 == 0:
            self.save_monitoring_data()
    
    def _update_statistics(self, monitor_id: str):
        """Update monitoring statistics."""
        history = self.monitoring_data[monitor_id]['history']
        
        if not history:
            return
        
        # Calculate uptime percentage
        successful = sum(1 for h in history if h['success'])
        uptime_percentage = (successful / len(history)) * 100 if history else 0
        
        # Calculate average response time
        response_times = [h['response_time'] for h in history if h['success']]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        # Find last downtime
        last_downtime = None
        for entry in reversed(history):
            if not entry['success']:
                last_downtime = entry['timestamp']
                break
        
        # Update stats
        self.monitoring_data[monitor_id]['stats'] = {
            'uptime_percentage': round(uptime_percentage, 2),
            'average_response_time': round(avg_response_time, 2),
            'last_downtime': last_downtime,
            'total_checks': len(history),
            'successful_checks': successful
        }
    
    def _check_alerts(self, monitor_id: str, config: Dict, success: bool):
        """Check if alerts should be triggered."""
        # Alert on consecutive failures
        if config['consecutive_failures'] >= 3:
            alert_data = {
                'type': 'consecutive_failures',
                'monitor_id': monitor_id,
                'host': config['host'],
                'failures': config['consecutive_failures'],
                'timestamp': datetime.now().isoformat()
            }
            self._trigger_alert(alert_data)
        
        # Alert on status change
        if hasattr(self, '_last_status'):
            last_status = getattr(self, f'_last_status_{monitor_id}', None)
            if last_status and last_status != config['status']:
                alert_data = {
                    'type': 'status_change',
                    'monitor_id': monitor_id,
                    'host': config['host'],
                    'old_status': last_status,
                    'new_status': config['status'],
                    'timestamp': datetime.now().isoformat()
                }
                self._trigger_alert(alert_data)
        
        setattr(self, f'_last_status_{monitor_id}', config['status'])
    
    def _trigger_alert(self, alert_data: Dict):
        """Trigger alert notifications."""
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception:
                pass
    
    def add_alert_callback(self, callback: Callable):
        """Add alert callback function."""
        self.alert_callbacks.append(callback)
    
    def get_monitoring_status(self) -> Dict:
        """Get current monitoring status."""
        status = {
            'monitoring_active': self.monitoring_active,
            'total_monitors': len(self.active_monitors),
            'monitors': {}
        }
        
        for monitor_id, config in self.active_monitors.items():
            monitor_status = {
                'host': config['host'],
                'type': config['type'],
                'status': config['status'],
                'last_check': config['last_check'].isoformat() if config['last_check'] else None,
                'consecutive_failures': config['consecutive_failures'],
                'total_checks': config['total_checks'],
                'successful_checks': config['successful_checks'],
                'success_rate': round((config['successful_checks'] / config['total_checks'] * 100), 2) if config['total_checks'] > 0 else 0
            }
            
            # Add statistics if available
            if monitor_id in self.monitoring_data:
                monitor_status['stats'] = self.monitoring_data[monitor_id]['stats']
            
            status['monitors'][monitor_id] = monitor_status
        
        return status
    
    def get_monitoring_history(self, monitor_id: str, hours: int = 24) -> List[Dict]:
        """
        Get monitoring history for a specific monitor.
        
        Args:
            monitor_id: Monitor identifier
            hours: Number of hours of history to return
            
        Returns:
            List of historical data points
        """
        if monitor_id not in self.monitoring_data:
            return []
        
        history = self.monitoring_data[monitor_id]['history']
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Filter by time range
        filtered_history = []
        for entry in history:
            try:
                entry_time = datetime.fromisoformat(entry['timestamp'])
                if entry_time >= cutoff_time:
                    filtered_history.append(entry)
            except Exception:
                continue
        
        return filtered_history
    
    def generate_monitoring_report(self, hours: int = 24) -> Dict:
        """
        Generate monitoring report.
        
        Args:
            hours: Time range for the report
            
        Returns:
            Monitoring report
        """
        report = {
            'report_time': datetime.now().isoformat(),
            'time_range_hours': hours,
            'summary': {
                'total_monitors': len(self.active_monitors),
                'monitors_up': 0,
                'monitors_down': 0,
                'average_uptime': 0,
                'total_alerts': 0
            },
            'monitors': {}
        }
        
        total_uptime = 0
        
        for monitor_id, config in self.active_monitors.items():
            if config['status'] == 'Up':
                report['summary']['monitors_up'] += 1
            else:
                report['summary']['monitors_down'] += 1
            
            # Get monitor statistics
            monitor_report = {
                'host': config['host'],
                'type': config['type'],
                'current_status': config['status'],
                'consecutive_failures': config['consecutive_failures']
            }
            
            if monitor_id in self.monitoring_data:
                stats = self.monitoring_data[monitor_id]['stats']
                monitor_report.update(stats)
                total_uptime += stats.get('uptime_percentage', 0)
            
            # Get recent history
            history = self.get_monitoring_history(monitor_id, hours)
            monitor_report['recent_checks'] = len(history)
            monitor_report['recent_failures'] = sum(1 for h in history if not h['success'])
            
            report['monitors'][monitor_id] = monitor_report
        
        # Calculate average uptime
        if report['summary']['total_monitors'] > 0:
            report['summary']['average_uptime'] = round(
                total_uptime / report['summary']['total_monitors'], 2
            )
        
        return report
    
    def stop_all_monitoring(self):
        """Stop all monitoring activities."""
        self.monitoring_active = False
        
        # Mark all monitors as inactive
        for config in self.active_monitors.values():
            config['active'] = False
        
        # Wait for threads to finish
        for thread in self.monitor_threads.values():
            if thread.is_alive():
                thread.join(timeout=2)
        
        # Save final data
        self.save_monitoring_data()
        
        # Clear active monitors
        self.active_monitors.clear()
        self.monitor_threads.clear()
    
    def export_monitoring_data(self, filename: str, format_type: str = "json") -> bool:
        """
        Export monitoring data to file.
        
        Args:
            filename: Output filename
            format_type: Export format (json, csv)
            
        Returns:
            True if export successful
        """
        try:
            if format_type.lower() == "json":
                with open(filename, 'w') as f:
                    json.dump(self.monitoring_data, f, indent=2, default=str)
                return True
            
            elif format_type.lower() == "csv":
                import csv
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Monitor', 'Timestamp', 'Success', 'Response Time', 'Details'])
                    
                    for monitor_id, data in self.monitoring_data.items():
                        for entry in data['history']:
                            writer.writerow([
                                monitor_id,
                                entry['timestamp'],
                                entry['success'],
                                entry['response_time'],
                                entry['details']
                            ])
                return True
            
        except Exception:
            return False
        
        return False
    
    def create_dashboard_data(self) -> Dict:
        """Create data for monitoring dashboard."""
        dashboard = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_monitors': len(self.active_monitors),
                'up': 0,
                'down': 0,
                'warning': 0
            },
            'monitors': [],
            'recent_alerts': [],
            'charts': {
                'uptime_trend': [],
                'response_time_trend': []
            }
        }
        
        for monitor_id, config in self.active_monitors.items():
            # Determine monitor status
            status = 'up'
            if config['status'] == 'Down':
                status = 'down'
                dashboard['summary']['down'] += 1
            elif config['consecutive_failures'] > 0:
                status = 'warning'
                dashboard['summary']['warning'] += 1
            else:
                dashboard['summary']['up'] += 1
            
            monitor_info = {
                'id': monitor_id,
                'host': config['host'],
                'type': config['type'],
                'status': status,
                'last_check': config['last_check'].isoformat() if config['last_check'] else None,
                'response_time': 0,
                'uptime': 0
            }
            
            # Add statistics
            if monitor_id in self.monitoring_data:
                stats = self.monitoring_data[monitor_id]['stats']
                monitor_info['uptime'] = stats.get('uptime_percentage', 0)
                monitor_info['response_time'] = stats.get('average_response_time', 0)
                
                # Add to trend data
                recent_history = self.get_monitoring_history(monitor_id, 6)  # Last 6 hours
                if recent_history:
                    uptime_points = []
                    response_points = []
                    
                    for i, entry in enumerate(recent_history[-12:]):  # Last 12 points
                        uptime_points.append({
                            'x': i,
                            'y': 100 if entry['success'] else 0
                        })
                        response_points.append({
                            'x': i,
                            'y': entry['response_time'] if entry['success'] else 0
                        })
                    
                    dashboard['charts']['uptime_trend'].append({
                        'monitor': monitor_id,
                        'data': uptime_points
                    })
                    dashboard['charts']['response_time_trend'].append({
                        'monitor': monitor_id,
                        'data': response_points
                    })
            
            dashboard['monitors'].append(monitor_info)
        
        return dashboard