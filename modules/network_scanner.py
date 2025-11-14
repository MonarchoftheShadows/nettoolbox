#!/usr/bin/env python3
"""
Network Scanner Module
Handles host discovery, port scanning, service detection, and OS fingerprinting

Author: NetTools Team
"""

import socket
import subprocess
import threading
import time
import ipaddress
# import nmap
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Union, Optional

try:
    import nmap
    NMAP_AVAILABLE = True
except Exception:
    NMAP_AVAILABLE = False



class NetworkScanner:
    """Network scanning functionality."""
    
    def __init__(self):
        """Initialize the network scanner."""
        self.nm = nmap.PortScanner()
        self.timeout = 3
        self.max_threads = 50
    
    def host_discovery(self, target: str) -> List[Dict]:
        """
        Discover active hosts in the network.
        
        Args:
            target: Network range (e.g., '192.168.1.0/24') or single host
            
        Returns:
            List of discovered hosts with their information
        """
        hosts = []
        
        try:
            # Use nmap for host discovery
            self.nm.scan(hosts=target, arguments='-sn -PE -PP -PM')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    host_info = {
                        'ip': host,
                        'hostname': self.nm[host].hostname() or 'Unknown',
                        'state': self.nm[host].state(),
                        'reason': self.nm[host]['status']['reason'],
                        'rtt': float(self.nm[host]['status'].get('reason_ttl', 0))
                    }
                    hosts.append(host_info)
            
        except Exception as e:
            # Fallback to ping sweep if nmap fails
            hosts = self._ping_sweep(target)
        
        return hosts
    
    def _ping_sweep(self, target: str) -> List[Dict]:
        """
        Perform ping sweep as fallback method.
        
        Args:
            target: Network range or single host
            
        Returns:
            List of responding hosts
        """
        hosts = []
        
        try:
            # Parse network range
            if '/' in target:
                network = ipaddress.IPv4Network(target, strict=False)
                host_list = [str(ip) for ip in network.hosts()]
            else:
                host_list = [target]
            
            # Limit hosts for performance
            if len(host_list) > 254:
                host_list = host_list[:254]
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_host = {executor.submit(self._ping_host, host): host 
                                for host in host_list}
                
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        result = future.result()
                        if result:
                            hosts.append(result)
                    except Exception:
                        continue
                        
        except Exception:
            pass
            
        return hosts
    
    def _ping_host(self, host: str) -> Optional[Dict]:
        """
        Ping a single host.
        
        Args:
            host: IP address to ping
            
        Returns:
            Host information if reachable, None otherwise
        """
        try:
            # Use system ping command
            if subprocess.os.name == 'nt':  # Windows
                cmd = f'ping -n 1 -w 1000 {host}'
            else:  # Unix/Linux
                cmd = f'ping -c 1 -W 1 {host}'
            
            result = subprocess.run(cmd.split(), capture_output=True, 
                                  text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                return {
                    'ip': host,
                    'hostname': self._resolve_hostname(host),
                    'state': 'up',
                    'reason': 'echo-reply',
                    'rtt': self._extract_rtt(result.stdout)
                }
        except Exception:
            pass
        
        return None
    
    def _resolve_hostname(self, ip: str) -> str:
        """Resolve hostname for IP address."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return 'Unknown'
    
    def _extract_rtt(self, ping_output: str) -> float:
        """Extract RTT from ping output."""
        try:
            if 'time=' in ping_output:
                time_part = ping_output.split('time=')[1].split()[0]
                return float(time_part.replace('ms', ''))
        except Exception:
            pass
        return 0.0
    
    def port_scan(self, target: str, port_range: str = "1-1000", 
                  scan_type: str = "tcp") -> List[Dict]:
        """
        Perform port scanning on target.
        
        Args:
            target: Target host IP
            port_range: Port range (e.g., "1-1000", "80,443,8080")
            scan_type: Type of scan ("tcp", "udp", "both")
            
        Returns:
            List of open ports with details
        """
        open_ports = []
        
        try:
            # Prepare nmap arguments
            if scan_type.lower() == "tcp":
                args = f'-sS -p {port_range}'
            elif scan_type.lower() == "udp":
                args = f'-sU -p {port_range}'
            elif scan_type.lower() == "both":
                args = f'-sS -sU -p {port_range}'
            else:
                args = f'-sS -p {port_range}'
            
            # Perform scan
            self.nm.scan(hosts=target, arguments=args)
            
            for host in self.nm.all_hosts():
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    
                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        if port_info['state'] in ['open', 'open|filtered']:
                            open_ports.append({
                                'port': port,
                                'protocol': protocol,
                                'state': port_info['state'],
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            })
            
        except Exception as e:
            # Fallback to socket-based scanning
            open_ports = self._socket_scan(target, port_range, scan_type)
        
        return open_ports
    
    def _socket_scan(self, target: str, port_range: str, 
                     scan_type: str) -> List[Dict]:
        """
        Socket-based port scanning fallback.
        
        Args:
            target: Target host
            port_range: Port range to scan
            scan_type: Scan type
            
        Returns:
            List of open ports
        """
        open_ports = []
        ports = self._parse_port_range(port_range)
        
        if scan_type.lower() in ["tcp", "both"]:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_port = {executor.submit(self._tcp_connect, target, port): port 
                                for port in ports}
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        if future.result():
                            service = self._get_service_name(port, 'tcp')
                            open_ports.append({
                                'port': port,
                                'protocol': 'tcp',
                                'state': 'open',
                                'service': service,
                                'version': '',
                                'product': '',
                                'extrainfo': ''
                            })
                    except Exception:
                        continue
        
        return open_ports
    
    def _parse_port_range(self, port_range: str) -> List[int]:
        """Parse port range string into list of ports."""
        ports = []
        
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                ports = list(range(start, min(end + 1, 65536)))
            elif ',' in port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
            else:
                ports = [int(port_range)]
        except Exception:
            ports = list(range(1, 1001))  # Default range
        
        return ports
    
    def _tcp_connect(self, host: str, port: int) -> bool:
        """Test TCP connection to port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _get_service_name(self, port: int, protocol: str) -> str:
        """Get service name for port."""
        try:
            service = socket.getservbyport(port, protocol)
            return service
        except Exception:
            # Common services mapping
            common_services = {
                20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
                25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3',
                143: 'imap', 443: 'https', 993: 'imaps', 995: 'pop3s',
                1433: 'mssql', 3306: 'mysql', 5432: 'postgresql',
                6379: 'redis', 27017: 'mongodb'
            }
            return common_services.get(port, 'unknown')
    
    def service_detection(self, target: str) -> List[Dict]:
        """
        Detect services and versions on open ports.
        
        Args:
            target: Target host
            
        Returns:
            List of detected services
        """
        services = []
        
        try:
            # Service detection scan
            self.nm.scan(hosts=target, arguments='-sV --version-intensity 5')
            
            for host in self.nm.all_hosts():
                for protocol in self.nm[host].all_protocols():
                    ports = self.nm[host][protocol].keys()
                    
                    for port in ports:
                        port_info = self.nm[host][protocol][port]
                        if port_info['state'] == 'open':
                            services.append({
                                'port': port,
                                'protocol': protocol,
                                'name': port_info.get('name', 'unknown'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'conf': port_info.get('conf', ''),
                                'method': port_info.get('method', '')
                            })
                            
        except Exception:
            pass
        
        return services
    
    def os_fingerprint(self, target: str) -> Union[Dict, str]:
        """
        Perform OS fingerprinting.
        
        Args:
            target: Target host
            
        Returns:
            OS information
        """
        try:
            # OS detection scan
            self.nm.scan(hosts=target, arguments='-O --osscan-guess')
            
            if target in self.nm.all_hosts():
                os_info = {}
                
                if 'osmatch' in self.nm[target]:
                    os_matches = self.nm[target]['osmatch']
                    if os_matches:
                        best_match = os_matches[0]
                        os_info['name'] = best_match.get('name', 'Unknown')
                        os_info['accuracy'] = best_match.get('accuracy', '0')
                        os_info['line'] = best_match.get('line', '')
                
                if 'osclass' in self.nm[target]:
                    os_classes = self.nm[target]['osclass']
                    if os_classes:
                        os_class = os_classes[0]
                        os_info['type'] = os_class.get('type', 'Unknown')
                        os_info['vendor'] = os_class.get('vendor', 'Unknown')
                        os_info['osfamily'] = os_class.get('osfamily', 'Unknown')
                        os_info['osgen'] = os_class.get('osgen', 'Unknown')
                
                if 'uptime' in self.nm[target]:
                    uptime = self.nm[target]['uptime']
                    os_info['uptime'] = f"{uptime.get('seconds', 0)} seconds"
                
                return os_info if os_info else "OS detection failed"
                
        except Exception:
            pass
        
        return "OS detection not available"
    
    def banner_grab(self, target: str, port: int, timeout: int = 5) -> Optional[str]:
        """
        Grab banner from service.
        
        Args:
            target: Target host
            port: Port number
            timeout: Connection timeout
            
        Returns:
            Service banner or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 443:
                # For HTTPS, we'd need SSL context
                pass
            else:
                # For other services, just wait for banner
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def traceroute(self, target: str) -> List[Dict]:
        """
        Perform traceroute to target.
        
        Args:
            target: Target host
            
        Returns:
            List of hops
        """
        import platform
        cmd = ["tracert", "-d", target] if platform.system() == "Windows" else ["traceroute", "-n", target]


        hops = []
        
        try:
            if subprocess.os.name == 'nt':  # Windows
                cmd = f'tracert -h 30 {target}'
            else:  # Unix/Linux
                cmd = f'traceroute -m 30 {target}'
            
            result = subprocess.run(cmd.split(), capture_output=True, 
                                  text=True, timeout=60)
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if line.strip() and not line.startswith('traceroute'):
                        hop_info = self._parse_traceroute_line(line)
                        if hop_info:
                            hops.append(hop_info)
                            
        except Exception:
            pass
        
        return hops
    
    def _parse_traceroute_line(self, line: str) -> Optional[Dict]:
        """Parse single traceroute line."""
        try:
            parts = line.strip().split()
            if len(parts) >= 3:
                hop_num = parts[0].rstrip('.')
                if hop_num.isdigit():
                    return {
                        'hop': int(hop_num),
                        'ip': parts[1] if '(' in parts[1] else 'unknown',
                        'hostname': parts[2] if '(' in parts[1] else parts[1],
                        'rtt': parts[-2] if 'ms' in parts[-1] else '0'
                    }
        except Exception:
            pass
        
        return None