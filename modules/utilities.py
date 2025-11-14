#!/usr/bin/env python3
"""
Utilities Module
Handles various network utilities and information gathering tools

Author: NetTools Team
"""

import socket
import subprocess
import requests
import re
import ipaddress
from typing import Dict, List, Optional, Union
import json
import time


class Utilities:
    """Network utilities and information gathering tools."""
    
    def __init__(self):
        """Initialize utilities."""
        self.timeout = 10
        
        # MAC vendor database (partial)
        self.mac_vendors = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:0C:29': 'VMware',
            '00:1C:42': 'Parallels',
            '00:16:3E': 'Xensource',
            '52:54:00': 'QEMU/KVM',
            '00:15:5D': 'Microsoft Hyper-V',
            '00:E0:4C': 'Realtek',
            'DC:A6:32': 'Raspberry Pi',
            'B8:27:EB': 'Raspberry Pi',
            '00:23:6C': 'Apple',
            '28:CF:E9': 'Apple',
            '3C:07:54': 'Apple',
            '00:1B:63': 'Apple',
            '44:45:53': 'Microsoft',
            '00:03:FF': 'Microsoft',
            '00:12:F0': 'Microsoft'
        }
    
    def dns_lookup(self, hostname: str, record_type: str = 'A') -> Dict:
        """
        Perform DNS lookup for hostname.
        
        Args:
            hostname: Hostname to resolve
            record_type: DNS record type (A, AAAA, MX, TXT, etc.)
            
        Returns:
            DNS lookup results
        """
        result = {
            'hostname': hostname,
            'record_type': record_type,
            'addresses': [],
            'records': [],
            'error': None
        }
        
        try:
            if record_type.upper() == 'A':
                # IPv4 addresses
                addresses = socket.gethostbyname_ex(hostname)
                result['addresses'] = addresses[2]
                result['records'] = [{'type': 'A', 'value': addr} for addr in addresses[2]]
                
            elif record_type.upper() == 'AAAA':
                # IPv6 addresses
                try:
                    addresses = socket.getaddrinfo(hostname, None, socket.AF_INET6)
                    ipv6_addrs = list(set([addr[4][0] for addr in addresses]))
                    result['addresses'] = ipv6_addrs
                    result['records'] = [{'type': 'AAAA', 'value': addr} for addr in ipv6_addrs]
                except socket.gaierror:
                    result['error'] = 'No IPv6 addresses found'
            
            else:
                # Use nslookup for other record types
                try:
                    cmd = f'nslookup -type={record_type} {hostname}'
                    output = subprocess.run(cmd.split(), capture_output=True, 
                                          text=True, timeout=self.timeout)
                    
                    if output.returncode == 0:
                        result['records'] = self._parse_nslookup_output(output.stdout, record_type)
                    else:
                        result['error'] = 'nslookup failed'
                        
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    result['error'] = 'nslookup not available or timeout'
                    
        except socket.gaierror as e:
            result['error'] = f'DNS resolution failed: {str(e)}'
        except Exception as e:
            result['error'] = f'Lookup error: {str(e)}'
        
        return result
    
    def _parse_nslookup_output(self, output: str, record_type: str) -> List[Dict]:
        """Parse nslookup output."""
        records = []
        lines = output.split('\n')
        
        for line in lines:
            line = line.strip()
            if record_type.upper() in line or 'answer:' in line.lower():
                # Basic parsing - this could be enhanced
                if '=' in line:
                    value = line.split('=')[-1].strip()
                    records.append({'type': record_type, 'value': value})
        
        return records
    
    def reverse_dns_lookup(self, ip_address: str) -> Dict:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip_address: IP address to resolve
            
        Returns:
            Reverse DNS results
        """
        result = {
            'ip_address': ip_address,
            'hostname': None,
            'error': None
        }
        
        try:
            hostname = socket.gethostbyaddr(ip_address)
            result['hostname'] = hostname[0]
        except socket.herror as e:
            result['error'] = f'Reverse DNS failed: {str(e)}'
        except Exception as e:
            result['error'] = f'Lookup error: {str(e)}'
        
        return result
    
    def whois_lookup(self, domain: str) -> Dict:
        """
        Perform WHOIS lookup.
        
        Args:
            domain: Domain to lookup
            
        Returns:
            WHOIS information
        """
        result = {
            'domain': domain,
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'raw_output': '',
            'error': None
        }
        
        try:
            # Try using whois command
            cmd = f'whois {domain}'
            output = subprocess.run(cmd.split(), capture_output=True, 
                                  text=True, timeout=self.timeout)
            
            if output.returncode == 0:
                result['raw_output'] = output.stdout
                result.update(self._parse_whois_output(output.stdout))
            else:
                result['error'] = 'WHOIS command failed'
                
        except subprocess.TimeoutExpired:
            result['error'] = 'WHOIS lookup timeout'
        except FileNotFoundError:
            result['error'] = 'WHOIS command not available'
        except Exception as e:
            result['error'] = f'WHOIS error: {str(e)}'
        
        return result
    
    def _parse_whois_output(self, output: str) -> Dict:
        """Parse WHOIS output."""
        info = {}
        lines = output.lower().split('\n')
        
        for line in lines:
            line = line.strip()
            
            if 'registrar:' in line:
                info['registrar'] = line.split(':', 1)[1].strip()
            elif 'creation date:' in line or 'created:' in line:
                info['creation_date'] = line.split(':', 1)[1].strip()
            elif 'expiration date:' in line or 'expires:' in line:
                info['expiration_date'] = line.split(':', 1)[1].strip()
            elif 'name server:' in line or 'nserver:' in line:
                ns = line.split(':', 1)[1].strip()
                if 'name_servers' not in info:
                    info['name_servers'] = []
                info['name_servers'].append(ns)
        
        return info
    
    def geoip_lookup(self, ip_address: str) -> Dict:
        """
        Perform GeoIP lookup.
        
        Args:
            ip_address: IP address to geolocate
            
        Returns:
            Geographic information
        """
        result = {
            'ip_address': ip_address,
            'country': None,
            'country_code': None,
            'region': None,
            'city': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'isp': None,
            'error': None
        }
        
        try:
            # Use free GeoIP service (ip-api.com)
            url = f'http://ip-api.com/json/{ip_address}'
            response = requests.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    result.update({
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp')
                    })
                else:
                    result['error'] = data.get('message', 'GeoIP lookup failed')
            else:
                result['error'] = f'HTTP {response.status_code}'
                
        except requests.RequestException as e:
            result['error'] = f'Request error: {str(e)}'
        except Exception as e:
            result['error'] = f'GeoIP error: {str(e)}'
        
        return result
    
    def mac_vendor_lookup(self, mac_address: str) -> Dict:
        """
        Lookup MAC address vendor.
        
        Args:
            mac_address: MAC address to lookup
            
        Returns:
            Vendor information
        """
        result = {
            'mac_address': mac_address,
            'vendor': None,
            'error': None
        }
        
        try:
            # Normalize MAC address
            mac_clean = mac_address.replace(':', '').replace('-', '').upper()
            
            if len(mac_clean) >= 6:
                # Check first 6 characters (OUI)
                oui = mac_clean[:6]
                oui_formatted = f'{oui[:2]}:{oui[2:4]}:{oui[4:6]}'
                
                # Check local database first
                if oui_formatted in self.mac_vendors:
                    result['vendor'] = self.mac_vendors[oui_formatted]
                else:
                    # Try online lookup
                    result['vendor'] = self._online_mac_lookup(oui)
            else:
                result['error'] = 'Invalid MAC address format'
                
        except Exception as e:
            result['error'] = f'MAC lookup error: {str(e)}'
        
        return result
    
    def _online_mac_lookup(self, oui: str) -> Optional[str]:
        """Perform online MAC vendor lookup."""
        try:
            # Use macvendors.com API
            url = f'https://api.macvendors.com/{oui}'
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                return response.text.strip()
            
        except Exception:
            pass
        
        return 'Unknown'
    
    def subnet_calculator(self, network: str) -> Dict:
        """
        Calculate subnet information.
        
        Args:
            network: Network in CIDR notation (e.g., 192.168.1.0/24)
            
        Returns:
            Subnet calculations
        """
        result = {
            'network': network,
            'network_address': None,
            'broadcast_address': None,
            'subnet_mask': None,
            'wildcard_mask': None,
            'total_hosts': 0,
            'usable_hosts': 0,
            'first_host': None,
            'last_host': None,
            'error': None
        }
        
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            
            result.update({
                'network_address': str(net.network_address),
                'broadcast_address': str(net.broadcast_address),
                'subnet_mask': str(net.netmask),
                'wildcard_mask': str(net.hostmask),
                'total_hosts': net.num_addresses,
                'usable_hosts': net.num_addresses - 2 if net.num_addresses > 2 else 0,
                'first_host': str(list(net.hosts())[0]) if list(net.hosts()) else None,
                'last_host': str(list(net.hosts())[-1]) if list(net.hosts()) else None
            })
            
        except ValueError as e:
            result['error'] = f'Invalid network: {str(e)}'
        except Exception as e:
            result['error'] = f'Calculation error: {str(e)}'
        
        return result
    
    def port_service_lookup(self, port: int, protocol: str = 'tcp') -> Dict:
        """
        Lookup service for port number.
        
        Args:
            port: Port number
            protocol: Protocol (tcp/udp)
            
        Returns:
            Service information
        """
        result = {
            'port': port,
            'protocol': protocol,
            'service': None,
            'description': None,
            'error': None
        }
        
        try:
            service = socket.getservbyport(port, protocol)
            result['service'] = service
            
            # Add common service descriptions
            descriptions = {
                21: 'File Transfer Protocol (FTP)',
                22: 'Secure Shell (SSH)',
                23: 'Telnet',
                25: 'Simple Mail Transfer Protocol (SMTP)',
                53: 'Domain Name System (DNS)',
                80: 'Hypertext Transfer Protocol (HTTP)',
                110: 'Post Office Protocol v3 (POP3)',
                143: 'Internet Message Access Protocol (IMAP)',
                443: 'HTTP Secure (HTTPS)',
                993: 'IMAP over SSL',
                995: 'POP3 over SSL',
                1433: 'Microsoft SQL Server',
                3306: 'MySQL Database',
                3389: 'Remote Desktop Protocol (RDP)',
                5432: 'PostgreSQL Database',
                6379: 'Redis Database',
                27017: 'MongoDB Database'
            }
            
            result['description'] = descriptions.get(port, f'{service} service')
            
        except OSError:
            result['error'] = f'No service found for port {port}/{protocol}'
        except Exception as e:
            result['error'] = f'Lookup error: {str(e)}'
        
        return result
    
    def network_interfaces(self) -> List[Dict]:
        """
        Get network interface information.
        
        Returns:
            List of network interfaces
        """
        interfaces = []
        
        try:
            # Try to get interface info using system commands
            if subprocess.os.name == 'nt':  # Windows
                cmd = 'ipconfig /all'
                output = subprocess.run(cmd, capture_output=True, text=True, 
                                      shell=True, timeout=self.timeout)
                interfaces = self._parse_ipconfig_output(output.stdout)
            else:  # Unix/Linux
                cmd = 'ifconfig -a'
                output = subprocess.run(cmd.split(), capture_output=True, 
                                      text=True, timeout=self.timeout)
                interfaces = self._parse_ifconfig_output(output.stdout)
                
        except Exception:
            # Fallback method
            try:
                import netifaces
                for interface in netifaces.interfaces():
                    addrs = netifaces.ifaddresses(interface)
                    iface_info = {'name': interface, 'addresses': addrs}
                    interfaces.append(iface_info)
            except ImportError:
                pass
        
        return interfaces
    
    def _parse_ipconfig_output(self, output: str) -> List[Dict]:
        """Parse Windows ipconfig output."""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line and not line.startswith(' '):
                if 'adapter' in line.lower():
                    if current_interface:
                        interfaces.append(current_interface)
                    current_interface = {'name': line, 'addresses': []}
            elif current_interface and ':' in line:
                key, value = line.split(':', 1)
                if 'ip' in key.lower() and value.strip():
                    current_interface['addresses'].append(value.strip())
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def _parse_ifconfig_output(self, output: str) -> List[Dict]:
        """Parse Unix/Linux ifconfig output."""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            if line and not line.startswith(' ') and not line.startswith('\t'):
                if current_interface:
                    interfaces.append(current_interface)
                interface_name = line.split(':')[0] if ':' in line else line.split()[0]
                current_interface = {'name': interface_name, 'addresses': []}
            elif current_interface and 'inet' in line:
                # Extract IP addresses
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current_interface['addresses'].append(ip_match.group(1))
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def bandwidth_test(self, test_url: str = None, test_size: str = "1MB") -> Dict:
        """
        Perform basic bandwidth test.
        
        Args:
            test_url: URL to download for testing
            test_size: Size of test data
            
        Returns:
            Bandwidth test results
        """
        result = {
            'test_url': test_url,
            'test_size': test_size,
            'download_speed_mbps': 0,
            'download_time_seconds': 0,
            'bytes_downloaded': 0,
            'error': None
        }
        
        if test_url is None:
            # Use a default test file
            test_url = 'http://httpbin.org/bytes/1048576'  # 1MB
        
        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=30, stream=True)
            
            if response.status_code == 200:
                total_bytes = 0
                for chunk in response.iter_content(chunk_size=8192):
                    total_bytes += len(chunk)
                
                end_time = time.time()
                download_time = end_time - start_time
                
                # Calculate speed in Mbps
                speed_bps = (total_bytes * 8) / download_time  # bits per second
                speed_mbps = speed_bps / (1024 * 1024)  # Mbps
                
                result.update({
                    'download_speed_mbps': round(speed_mbps, 2),
                    'download_time_seconds': round(download_time, 2),
                    'bytes_downloaded': total_bytes
                })
            else:
                result['error'] = f'HTTP {response.status_code}'
                
        except requests.RequestException as e:
            result['error'] = f'Request error: {str(e)}'
        except Exception as e:
            result['error'] = f'Test error: {str(e)}'
        
        return result
    
    def get_public_ip(self) -> Dict:
        """
        Get public IP address.
        
        Returns:
            Public IP information
        """
        result = {
            'public_ip': None,
            'source': None,
            'error': None
        }
        
        # List of public IP services
        services = [
            'https://api.ipify.org',
            'https://ifconfig.me/ip',
            'https://ipecho.net/plain',
            'https://myexternalip.com/raw',
            'https://wtfismyip.com/text'
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    # Validate IP format
                    ipaddress.ip_address(ip)
                    result['public_ip'] = ip
                    result['source'] = service
                    break
            except Exception:
                continue
        
        if not result['public_ip']:
            result['error'] = 'Unable to determine public IP'
        
        return result
    
    def traceroute(self, target: str, max_hops: int = 30) -> List[Dict]:
        """
        Perform traceroute to target.
        
        Args:
            target: Target host or IP
            max_hops: Maximum number of hops
            
        Returns:
            List of traceroute hops
        """
        hops = []
        
        try:
            if subprocess.os.name == 'nt':  # Windows
                cmd = f'tracert -h {max_hops} {target}'
            else:  # Unix/Linux
                cmd = f'traceroute -m {max_hops} {target}'
            
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            hop_num = 0
            for line in process.stdout:
                line = line.strip()
                if line and not line.startswith('traceroute'):
                    hop_info = self._parse_traceroute_line(line, hop_num)
                    if hop_info:
                        hops.append(hop_info)
                        hop_num += 1
            
            process.wait(timeout=60)
            
        except subprocess.TimeoutExpired:
            hops.append({'error': 'Traceroute timeout'})
        except Exception as e:
            hops.append({'error': f'Traceroute error: {str(e)}'})
        
        return hops
    
    def _parse_traceroute_line(self, line: str, hop_num: int) -> Optional[Dict]:
        """Parse traceroute output line."""
        try:
            parts = line.strip().split()
            
            if len(parts) >= 3:
                # Try to extract hop number, IP, and timing
                if parts[0].isdigit() or parts[0].rstrip('.').isdigit():
                    hop_number = int(parts[0].rstrip('.'))
                    
                    # Look for IP address
                    ip_address = None
                    hostname = None
                    rtts = []
                    
                    for part in parts[1:]:
                        # Check for IP in parentheses
                        if '(' in part and ')' in part:
                            ip_address = part.strip('()')
                        # Check for standalone IP
                        elif self._is_ip_address(part):
                            ip_address = part
                        # Check for hostname
                        elif '.' in part and not part.endswith('ms') and not part.isdigit():
                            hostname = part
                        # Check for RTT
                        elif part.endswith('ms'):
                            try:
                                rtt = float(part[:-2])
                                rtts.append(rtt)
                            except ValueError:
                                pass
                    
                    return {
                        'hop': hop_number,
                        'ip_address': ip_address,
                        'hostname': hostname,
                        'rtts': rtts,
                        'avg_rtt': sum(rtts) / len(rtts) if rtts else 0
                    }
        except Exception:
            pass
        
        return None
    
    def _is_ip_address(self, text: str) -> bool:
        """Check if text is a valid IP address."""
        try:
            ipaddress.ip_address(text)
            return True
        except ValueError:
            return False
    
    def network_scan_summary(self, network: str) -> Dict:
        """
        Create network scan summary.
        
        Args:
            network: Network to summarize
            
        Returns:
            Network summary
        """
        summary = {
            'network': network,
            'network_info': {},
            'estimated_scan_time': {},
            'recommended_scan_types': [],
            'security_considerations': []
        }
        
        try:
            # Calculate network information
            net = ipaddress.IPv4Network(network, strict=False)
            
            summary['network_info'] = {
                'network_address': str(net.network_address),
                'broadcast_address': str(net.broadcast_address),
                'total_hosts': net.num_addresses,
                'usable_hosts': net.num_addresses - 2 if net.num_addresses > 2 else 0,
                'subnet_mask': str(net.netmask),
                'prefix_length': net.prefixlen
            }
            
            # Estimate scan times
            host_count = net.num_addresses
            summary['estimated_scan_time'] = {
                'ping_sweep': f'{host_count / 50:.1f} seconds',
                'port_scan_top_100': f'{host_count * 2:.0f} seconds',
                'port_scan_all': f'{host_count * 60:.0f} seconds',
                'service_detection': f'{host_count * 30:.0f} seconds'
            }
            
            # Recommend scan types based on network size
            if host_count <= 254:  # /24 or smaller
                summary['recommended_scan_types'] = [
                    'Full ping sweep',
                    'Top 1000 port scan',
                    'Service version detection',
                    'OS fingerprinting'
                ]
            elif host_count <= 65534:  # /16
                summary['recommended_scan_types'] = [
                    'Ping sweep with threading',
                    'Top 100 port scan',
                    'Service detection on common ports'
                ]
            else:  # Larger networks
                summary['recommended_scan_types'] = [
                    'Targeted ping sweep',
                    'Common port scan only',
                    'Banner grabbing'
                ]
            
            # Security considerations
            if net.is_private:
                summary['security_considerations'] = [
                    'Private network - scanning should be safe',
                    'Consider rate limiting for large networks',
                    'Document authorized scanning in corporate environments'
                ]
            else:
                summary['security_considerations'] = [
                    'PUBLIC NETWORK - Ensure you have authorization',
                    'Use minimal scanning techniques',
                    'Respect rate limits and terms of service',
                    'Consider legal implications'
                ]
                
        except ValueError as e:
            summary['error'] = f'Invalid network: {str(e)}'
        
        return summary
    
    def generate_report(self, scan_data: Dict, report_type: str = "summary") -> str:
        """
        Generate formatted report from scan data.
        
        Args:
            scan_data: Scan results data
            report_type: Type of report (summary, detailed, json)
            
        Returns:
            Formatted report string
        """
        if report_type.lower() == "json":
            return json.dumps(scan_data, indent=2, default=str)
        
        report_lines = []
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        # Header
        report_lines.extend([
            "=" * 60,
            f"NETWORK SECURITY SCAN REPORT",
            f"Generated: {timestamp}",
            "=" * 60,
            ""
        ])
        
        # Summary section
        if 'target' in scan_data:
            report_lines.extend([
                f"Target: {scan_data['target']}",
                f"Scan Type: {scan_data.get('scan_type', 'Unknown')}",
                ""
            ])
        
        # Results sections based on data type
        if 'hosts' in scan_data:
            report_lines.extend([
                f"DISCOVERED HOSTS ({len(scan_data['hosts'])})",
                "-" * 30
            ])
            for host in scan_data['hosts']:
                report_lines.append(f"  {host.get('ip', 'Unknown')} - {host.get('hostname', 'No hostname')}")
            report_lines.append("")
        
        if 'ports' in scan_data:
            total_ports = sum(len(ports) for ports in scan_data['ports'].values())
            report_lines.extend([
                f"OPEN PORTS ({total_ports})",
                "-" * 20
            ])
            for host, ports in scan_data['ports'].items():
                if ports:
                    report_lines.append(f"  Host: {host}")
                    for port in ports:
                        service = port.get('service', 'unknown')
                        report_lines.append(f"    {port.get('port', '?')}/{port.get('protocol', 'tcp')} - {service}")
            report_lines.append("")
        
        if 'vulnerabilities' in scan_data:
            report_lines.extend([
                f"VULNERABILITIES ({len(scan_data['vulnerabilities'])})",
                "-" * 25
            ])
            for vuln in scan_data['vulnerabilities']:
                risk = vuln.get('confidence', 'Unknown')
                vuln_type = vuln.get('type', 'Unknown')
                report_lines.append(f"  [{risk}] {vuln_type} - {vuln.get('url', vuln.get('target', ''))}")
            report_lines.append("")
        
        # Recommendations
        if report_type.lower() == "detailed":
            report_lines.extend([
                "RECOMMENDATIONS",
                "-" * 15,
                "• Change default passwords on discovered services",
                "• Update software versions with known vulnerabilities", 
                "• Implement network segmentation where appropriate",
                "• Monitor for unusual network activity",
                "• Regular security assessments recommended",
                ""
            ])
        
        # Footer
        report_lines.extend([
            "=" * 60,
            "End of Report",
            "=" * 60
        ])
        
        return "\n".join(report_lines)