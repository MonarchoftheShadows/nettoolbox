#!/usr/bin/env python3
"""
Packet Analyzer Module
Handles packet sniffing, analysis, and monitoring

Author: NetTools Team
"""

import time
import threading
from datetime import datetime
from typing import List, Dict, Optional, Callable
try:
    from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP, ARP, DNS
    from scapy.all import get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketAnalyzer:
    """Network packet analysis and sniffing functionality."""
    
    def __init__(self):
        """Initialize the packet analyzer."""
        self.is_sniffing = False
        self.captured_packets = []
        self.sniff_thread = None
        self.packet_count = 0
        self.sniff_filter = ""
        self.interface = None
        
        if not SCAPY_AVAILABLE:
            self.available = False
            self.error_message = "Scapy library not available. Install with: pip install scapy"
        else:
            self.available = True
            self.error_message = None
    
    def get_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces.
        
        Returns:
            List of interface names
        """
        if not self.available:
            return []
        
        try:
            return get_if_list()
        except Exception:
            return []
    
    def start_sniffing(self, interface: str = None, packet_filter: str = "", 
                      packet_count: int = 0, callback: Callable = None) -> bool:
        """
        Start packet sniffing.
        
        Args:
            interface: Network interface to sniff on
            packet_filter: BPF filter string
            packet_count: Number of packets to capture (0 = infinite)
            callback: Callback function for each packet
            
        Returns:
            True if sniffing started successfully
        """
        if not self.available:
            return False
        
        if self.is_sniffing:
            return False
        
        try:
            self.interface = interface
            self.sniff_filter = packet_filter
            self.captured_packets = []
            self.packet_count = 0
            self.is_sniffing = True
            
            # Start sniffing in separate thread
            self.sniff_thread = threading.Thread(
                target=self._sniff_worker,
                args=(interface, packet_filter, packet_count, callback)
            )
            self.sniff_thread.daemon = True
            self.sniff_thread.start()
            
            return True
            
        except Exception:
            self.is_sniffing = False
            return False
    
    def stop_sniffing(self):
        """Stop packet sniffing."""
        self.is_sniffing = False
        if self.sniff_thread and self.sniff_thread.is_alive():
            self.sniff_thread.join(timeout=2)
    
    def _sniff_worker(self, interface: str, packet_filter: str, 
                     count: int, callback: Callable):
        """Worker thread for packet sniffing."""
        try:
            def packet_handler(packet):
                if not self.is_sniffing:
                    return
                
                self.packet_count += 1
                self.captured_packets.append(packet)
                
                # Limit stored packets to prevent memory issues
                if len(self.captured_packets) > 1000:
                    self.captured_packets = self.captured_packets[-500:]
                
                if callback:
                    try:
                        callback(packet)
                    except Exception:
                        pass
            
            # Configure sniffing parameters
            sniff_params = {
                'prn': packet_handler,
                'store': 0,  # Don't store packets in scapy
                'stop_filter': lambda x: not self.is_sniffing
            }
            
            if interface:
                sniff_params['iface'] = interface
            if packet_filter:
                sniff_params['filter'] = packet_filter
            if count > 0:
                sniff_params['count'] = count
            
            sniff(**sniff_params)
            
        except Exception:
            pass
        finally:
            self.is_sniffing = False
    
    def analyze_packet(self, packet) -> Dict:
        """
        Analyze a single packet and extract information.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary with packet analysis
        """
        if not self.available:
            return {}
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'size': len(packet),
            'protocols': [],
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'protocol': None,
            'info': {}
        }
        
        try:
            # Check for IP layer
            if IP in packet:
                ip_layer = packet[IP]
                analysis['src_ip'] = ip_layer.src
                analysis['dst_ip'] = ip_layer.dst
                analysis['protocols'].append('IP')
                analysis['info']['ip_version'] = ip_layer.version
                analysis['info']['ttl'] = ip_layer.ttl
                analysis['info']['length'] = ip_layer.len
                
                # Check transport layer
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    analysis['src_port'] = tcp_layer.sport
                    analysis['dst_port'] = tcp_layer.dport
                    analysis['protocol'] = 'TCP'
                    analysis['protocols'].append('TCP')
                    analysis['info']['flags'] = tcp_layer.flags
                    analysis['info']['seq'] = tcp_layer.seq
                    analysis['info']['ack'] = tcp_layer.ack
                    
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    analysis['src_port'] = udp_layer.sport
                    analysis['dst_port'] = udp_layer.dport
                    analysis['protocol'] = 'UDP'
                    analysis['protocols'].append('UDP')
                    analysis['info']['length'] = udp_layer.len
                    
                elif ICMP in packet:
                    icmp_layer = packet[ICMP]
                    analysis['protocol'] = 'ICMP'
                    analysis['protocols'].append('ICMP')
                    analysis['info']['type'] = icmp_layer.type
                    analysis['info']['code'] = icmp_layer.code
            
            # Check for ARP
            elif ARP in packet:
                arp_layer = packet[ARP]
                analysis['protocols'].append('ARP')
                analysis['protocol'] = 'ARP'
                analysis['src_ip'] = arp_layer.psrc
                analysis['dst_ip'] = arp_layer.pdst
                analysis['info']['operation'] = arp_layer.op
                analysis['info']['src_mac'] = arp_layer.hwsrc
                analysis['info']['dst_mac'] = arp_layer.hwdst
            
            # Check for DNS
            if DNS in packet:
                dns_layer = packet[DNS]
                analysis['protocols'].append('DNS')
                analysis['info']['dns_id'] = dns_layer.id
                analysis['info']['dns_qr'] = dns_layer.qr
                analysis['info']['dns_opcode'] = dns_layer.opcode
                
                if dns_layer.qd:
                    analysis['info']['dns_query'] = dns_layer.qd.qname.decode()
            
            # Extract payload information
            if packet.payload:
                payload = bytes(packet.payload)
                analysis['info']['payload_size'] = len(payload)
                
                # Check for common protocols in payload
                payload_str = payload.decode('utf-8', errors='ignore').lower()
                if 'http' in payload_str[:100]:
                    analysis['protocols'].append('HTTP')
                elif 'ftp' in payload_str[:50]:
                    analysis['protocols'].append('FTP')
                elif 'smtp' in payload_str[:50]:
                    analysis['protocols'].append('SMTP')
                    
        except Exception:
            pass
        
        return analysis
    
    def get_packet_summary(self) -> Dict:
        """
        Get summary of captured packets.
        
        Returns:
            Summary statistics
        """
        if not self.captured_packets:
            return {'total': 0}
        
        summary = {
            'total': len(self.captured_packets),
            'protocols': {},
            'top_sources': {},
            'top_destinations': {},
            'port_stats': {}
        }
        
        try:
            for packet in self.captured_packets[-100:]:  # Analyze last 100 packets
                analysis = self.analyze_packet(packet)
                
                # Count protocols
                for protocol in analysis.get('protocols', []):
                    summary['protocols'][protocol] = summary['protocols'].get(protocol, 0) + 1
                
                # Count source IPs
                src_ip = analysis.get('src_ip')
                if src_ip:
                    summary['top_sources'][src_ip] = summary['top_sources'].get(src_ip, 0) + 1
                
                # Count destination IPs
                dst_ip = analysis.get('dst_ip')
                if dst_ip:
                    summary['top_destinations'][dst_ip] = summary['top_destinations'].get(dst_ip, 0) + 1
                
                # Count ports
                dst_port = analysis.get('dst_port')
                if dst_port:
                    summary['port_stats'][dst_port] = summary['port_stats'].get(dst_port, 0) + 1
            
            # Sort and limit results
            summary['top_sources'] = dict(sorted(summary['top_sources'].items(), 
                                               key=lambda x: x[1], reverse=True)[:10])
            summary['top_destinations'] = dict(sorted(summary['top_destinations'].items(), 
                                                    key=lambda x: x[1], reverse=True)[:10])
            summary['port_stats'] = dict(sorted(summary['port_stats'].items(), 
                                               key=lambda x: x[1], reverse=True)[:10])
            
        except Exception:
            pass
        
        return summary
    
    def save_capture(self, filename: str) -> bool:
        """
        Save captured packets to file.
        
        Args:
            filename: Output filename
            
        Returns:
            True if successful
        """
        if not self.available or not self.captured_packets:
            return False
        
        try:
            wrpcap(filename, self.captured_packets)
            return True
        except Exception:
            return False
    
    def load_capture(self, filename: str) -> bool:
        """
        Load packets from file.
        
        Args:
            filename: Input filename
            
        Returns:
            True if successful
        """
        if not self.available:
            return False
        
        try:
            self.captured_packets = rdpcap(filename)
            return True
        except Exception:
            return False
    
    def filter_packets(self, filter_criteria: Dict) -> List:
        """
        Filter captured packets based on criteria.
        
        Args:
            filter_criteria: Dictionary with filter parameters
            
        Returns:
            List of filtered packets
        """
        if not self.captured_packets:
            return []
        
        filtered = []
        
        try:
            for packet in self.captured_packets:
                analysis = self.analyze_packet(packet)
                match = True
                
                # Apply filters
                if 'protocol' in filter_criteria:
                    if analysis.get('protocol') != filter_criteria['protocol']:
                        match = False
                
                if 'src_ip' in filter_criteria:
                    if analysis.get('src_ip') != filter_criteria['src_ip']:
                        match = False
                
                if 'dst_ip' in filter_criteria:
                    if analysis.get('dst_ip') != filter_criteria['dst_ip']:
                        match = False
                
                if 'port' in filter_criteria:
                    src_port = analysis.get('src_port')
                    dst_port = analysis.get('dst_port')
                    if (src_port != filter_criteria['port'] and 
                        dst_port != filter_criteria['port']):
                        match = False
                
                if match:
                    filtered.append(packet)
                    
        except Exception:
            pass
        
        return filtered
    
    def detect_suspicious_activity(self) -> List[Dict]:
        """
        Detect suspicious network activity.
        
        Returns:
            List of suspicious activities detected
        """
        if not self.captured_packets:
            return []
        
        suspicious = []
        
        try:
            # Analyze recent packets for suspicious patterns
            recent_packets = self.captured_packets[-50:]
            
            # Port scan detection
            port_scan_threshold = 10
            src_to_ports = {}
            
            for packet in recent_packets:
                analysis = self.analyze_packet(packet)
                src_ip = analysis.get('src_ip')
                dst_port = analysis.get('dst_port')
                
                if src_ip and dst_port and analysis.get('protocol') == 'TCP':
                    if src_ip not in src_to_ports:
                        src_to_ports[src_ip] = set()
                    src_to_ports[src_ip].add(dst_port)
            
            # Check for port scanning
            for src_ip, ports in src_to_ports.items():
                if len(ports) >= port_scan_threshold:
                    suspicious.append({
                        'type': 'Port Scan',
                        'source': src_ip,
                        'details': f'Scanned {len(ports)} ports',
                        'severity': 'High'
                    })
            
            # ARP spoofing detection
            arp_table = {}
            for packet in recent_packets:
                if ARP in packet:
                    arp_layer = packet[ARP]
                    ip = arp_layer.psrc
                    mac = arp_layer.hwsrc
                    
                    if ip in arp_table and arp_table[ip] != mac:
                        suspicious.append({
                            'type': 'ARP Spoofing',
                            'source': ip,
                            'details': f'MAC changed from {arp_table[ip]} to {mac}',
                            'severity': 'High'
                        })
                    
                    arp_table[ip] = mac
            
            # Detect unusual traffic patterns
            packet_rate = len(recent_packets) / 60  # packets per second
            if packet_rate > 100:  # High packet rate
                suspicious.append({
                    'type': 'High Traffic Rate',
                    'source': 'Network',
                    'details': f'{packet_rate:.2f} packets/second',
                    'severity': 'Medium'
                })
                
        except Exception:
            pass
        
        return suspicious
    
    def get_status(self) -> Dict:
        """
        Get current status of packet analyzer.
        
        Returns:
            Status information
        """
        return {
            'available': self.available,
            'is_sniffing': self.is_sniffing,
            'packet_count': self.packet_count,
            'captured_packets': len(self.captured_packets) if self.captured_packets else 0,
            'interface': self.interface,
            'filter': self.sniff_filter,
            'error_message': self.error_message
        }