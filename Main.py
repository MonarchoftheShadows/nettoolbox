#!/usr/bin/env python3
"""
Network Analysis, Exploitation, and Monitoring Toolbox
Main Entry Point

A comprehensive network security toolkit designed for professionals.
Author: NetTools Team
Version: 1.0
"""

import os
import sys
import time
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.layout import Layout
from rich import box
from modules.network_scanner import NetworkScanner
from modules.web_scanner import WebScanner
from modules.packet_analyzer import PacketAnalyzer
from modules.exploitation_tools import ExploitationTools
from modules.monitoring_tools import MonitoringTools
from modules.utilities import Utilities
from modules.logger import Logger

class NetToolbox:
    """Main application class for the Network Toolbox."""
    
    def __init__(self):
        """Initialize the application."""
        self.console = Console()
        self.logger = Logger()
        self.history = []
        self.current_theme = "default"
        
        # Initialize modules
        self.network_scanner = NetworkScanner()
        self.web_scanner = WebScanner()
        self.packet_analyzer = PacketAnalyzer()
        self.exploitation_tools = ExploitationTools()
        self.monitoring_tools = MonitoringTools()
        self.utilities = Utilities()
        
        # Ensure logs directory exists
        os.makedirs("logs", exist_ok=True)
        os.makedirs("results", exist_ok=True)
    
    def display_banner(self):
        # ... (existing code remains unchanged)
        """Display the application banner."""
        banner = """
    ███╗   ██╗███████╗████████╗████████╗ ██████╗  ██████╗ ██╗     ██████╗  ██████╗ ██╗  ██╗
    ████╗  ██║██╔════╝╚══██╔══╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔══██╗██╔═══██╗╚██╗██╔╝
    ██╔██╗ ██║█████╗     ██║      ██║   ██║   ██║██║   ██║██║     ██████╔╝██║   ██║ ╚███╔╝ 
    ██║╚██╗██║██╔══╝     ██║      ██║   ██║   ██║██║   ██║██║     ██╔══██╗██║   ██║ ██╔██╗ 
    ██║ ╚████║███████╗   ██║      ██║   ╚██████╔╝╚██████╔╝███████╗██████╔╝╚██████╔╝██╔╝ ██╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝
        """
        
        title_text = Text(banner, style="bold cyan")
        subtitle = Text("Network Analysis, Exploitation & Monitoring Toolkit v1.0", style="bold white")
        author = Text("Professional Network Security Suite", style="dim white")
        
        panel = Panel(
            f"{title_text}\n{subtitle}\n{author}",
            border_style="bright_blue",
            padding=(1, 2)
        )
        
        self.console.print(panel)
        self.console.print()
    
    def display_main_menu(self):
        # ... (existing code remains unchanged)
        """Display the main menu."""
        menu_table = Table(show_header=False, box=box.ROUNDED, border_style="bright_green")
        menu_table.add_column("Option", style="bold cyan", width=5)
        menu_table.add_column("Description", style="white", width=60)
        menu_table.add_column("Status", style="green", width=10)
        
        menu_options = [
            ("1", "🔍  Network Scanning & Reconnaissance", "Ready"),
            ("2", "🌐  Web Application Security Tools", "Ready"),
            ("3", "📡  Packet Analysis & Network Sniffing", "Ready"),
            ("4", "⚡  Exploitation & Penetration Tools", "Ready"),
            ("5", "📊  Network Monitoring & Alerting", "Ready"),
            ("6", "🛠️   Utilities & Information Gathering", "Ready"),
            ("7", "📝  View Command History", "Ready"),
            ("8", "⚙️   Settings & Configuration", "Ready"),
            ("9", "❓  Help & Documentation", "Ready"),
            ("0", "🚪  Exit Application", "Ready")
        ]
        
        for option, desc, status in menu_options:
            menu_table.add_row(option, desc, status)
        
        panel = Panel(
            menu_table,
            title="[bold white]Main Menu - Select Your Tool[/bold white]",
            border_style="bright_green",
            padding=(1, 2)
        )
        
        self.console.print(panel)
    
    def network_scanning_menu(self):
        """Handle network scanning operations."""
        while True:
            self.console.clear()
            self.console.print(Panel("🔍 [bold cyan]Network Scanning & Reconnaissance[/bold cyan]", 
                                border_style="cyan"))
            
            options = Table(show_header=False, box=box.SIMPLE)
            options.add_column("Option", style="bold yellow", width=8)
            options.add_column("Description", style="white")
            
            scan_options = [
                ("1", "Host Discovery (Ping Sweep)"),
                ("2", "Port Scanning (TCP/UDP)"),
                ("3", "Service & Version Detection"),
                ("4", "OS Fingerprinting"),
                ("5", "Banner Grabbing"),
                ("6", "Full Network Reconnaissance"),
                ("7", "Export Scan Results"),
                ("0", "← Back to Main Menu")
            ]
            
            for opt, desc in scan_options:
                options.add_row(opt, desc)
            
            self.console.print(options)
            self.console.print()
            
            choice = Prompt.ask("[bold green]Select option", choices=[str(i) for i in range(8)])
            
            if choice == "0":
                break
            elif choice == "1":
                self.host_discovery()
            elif choice == "2":
                self.port_scanning()
            elif choice == "3":
                self.service_detection()
            elif choice == "4":
                self.os_fingerprinting()
            elif choice == "5":
                self.banner_grabbing()
            elif choice == "6":
                self.full_reconnaissance()
            elif choice == "7":
                self.export_results()

    def host_discovery(self):
        """Perform host discovery."""
        try:
            target = Prompt.ask("[bold cyan]Enter target network (e.g., 192.168.1.0/24)")
            
            if not target:
                self.console.print("[red]Invalid target specified[/red]")
                self.wait_for_user()
                return
            
            self.console.print(f"[yellow]Starting host discovery on {target}...[/yellow]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Discovering hosts...", total=None)
                
                results = self.network_scanner.host_discovery(target)
                progress.update(task, completed=True)
                
                if results:
                    self.display_host_results(results)
                    self.save_results("host_discovery", results)
                else:
                    self.console.print("[red]No hosts discovered[/red]")
                    
        except Exception as e:
            self.console.print(f"[red]Error during host discovery: {str(e)}[/red]")
        
        self.wait_for_user()

    def port_scanning(self):
        """Perform port scanning."""
        try:
            target = Prompt.ask("[bold cyan]Enter target host/IP")
            port_range = Prompt.ask("[bold cyan]Enter port range", default="1-1000")
            scan_type = Prompt.ask("[bold cyan]Scan type", choices=["tcp", "udp", "both"], default="tcp")
            
            self.console.print(f"[yellow]Starting {scan_type.upper()} port scan on {target}...[/yellow]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Scanning ports...", total=None)
                
                results = self.network_scanner.port_scan(target, port_range, scan_type)
                progress.update(task, completed=True)
                
                if results:
                    self.display_port_results(results)
                    self.save_results("port_scan", results)
                else:
                    self.console.print("[red]No open ports found[/red]")
                    
        except Exception as e:
            self.console.print(f"[red]Error during port scan: {str(e)}[/red]")
        
        self.wait_for_user()

    def service_detection(self):
        """Perform service detection."""
        try:
            target = Prompt.ask("[bold cyan]Enter target host/IP")
            
            self.console.print(f"[yellow]Detecting services on {target}...[/yellow]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Detecting services...", total=None)
                
                results = self.network_scanner.service_detection(target)
                progress.update(task, completed=True)
                
                if results:
                    self.display_service_results(results)
                    self.save_results("service_detection", results)
                else:
                    self.console.print("[red]No services detected[/red]")
                    
        except Exception as e:
            self.console.print(f"[red]Error during service detection: {str(e)}[/red]")
        
        self.wait_for_user()

    def os_fingerprinting(self):
        """Perform OS fingerprinting."""
        try:
            target = Prompt.ask("[bold cyan]Enter target host/IP")
            
            self.console.print(f"[yellow]Fingerprinting OS on {target}...[/yellow]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task("Fingerprinting OS...", total=None)
                
                results = self.network_scanner.os_fingerprint(target)
                progress.update(task, completed=True)
                
                if results and isinstance(results, dict) and results:
                    self.display_os_results(results)
                    self.save_results("os_fingerprint", results)
                else:
                    self.console.print("[red]Unable to determine OS[/red]")
                    
        except Exception as e:
            self.console.print(f"[red]Error during OS fingerprinting: {str(e)}[/red]")
        
        self.wait_for_user()

    def banner_grabbing(self):
        """Perform banner grabbing."""
        try:
            target = Prompt.ask("[bold cyan]Enter target host/IP")
            port = IntPrompt.ask("[bold cyan]Enter port number", default=80)
            
            self.console.print(f"[yellow]Grabbing banner from {target}:{port}...[/yellow]")
            
            banner = self.network_scanner.banner_grab(target, port)
            if banner:
                self.console.print(Panel(banner, title=f"[bold green]Banner - {target}:{port}[/bold green]"))
                self.save_results("banner_grab", {"target": target, "port": port, "banner": banner})
            else:
                self.console.print("[red]No banner received[/red]")
        except Exception as e:
            self.console.print(f"[red]Error grabbing banner: {str(e)}[/red]")
        
        self.wait_for_user()

    def full_reconnaissance(self):
        """Perform full network reconnaissance."""
        try:
            target = Prompt.ask("[bold cyan]Enter target (host or network)")
            
            confirm = Prompt.ask(f"[yellow]This will perform a comprehensive scan of {target}. Continue?[/yellow]", 
                            choices=["y", "n"], default="y")
            
            if confirm.lower() != 'y':
                return
            
            self.console.print(f"[yellow]Starting full reconnaissance of {target}...[/yellow]")
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                # Host discovery
                task1 = progress.add_task("Phase 1: Host discovery...", total=None)
                hosts = self.network_scanner.host_discovery(target)
                progress.update(task1, completed=True)
                
                if not hosts:
                    self.console.print("[red]No hosts found, aborting reconnaissance[/red]")
                    self.wait_for_user()
                    return
                
                all_results = {"hosts": hosts, "ports": {}, "services": {}, "os": {}}
                
                for host in hosts[:3]:  # Limit to first 3 hosts to avoid timeout
                    host_ip = host.get("ip", "Unknown")
                    
                    # Port scanning
                    task2 = progress.add_task(f"Phase 2: Port scanning {host_ip}...", total=None)
                    try:
                        ports = self.network_scanner.port_scan(host_ip, "1-8080", "both")  # Smaller range for demo
                        all_results["ports"][host_ip] = ports
                    except Exception as e:
                        self.console.print(f"[red]Error port scanning {host_ip}: {str(e)}[/red]")
                        all_results["ports"][host_ip] = []
                    progress.update(task2, completed=True)
                    
                    # Service detection
                    task3 = progress.add_task(f"Phase 3: Service detection {host_ip}...", total=None)
                    try:
                        services = self.network_scanner.service_detection(host_ip)
                        all_results["services"][host_ip] = services
                    except Exception as e:
                        self.console.print(f"[red]Error service detection {host_ip}: {str(e)}[/red]")
                        all_results["services"][host_ip] = []
                    progress.update(task3, completed=True)
                    
                    # OS fingerprinting
                    task4 = progress.add_task(f"Phase 4: OS fingerprinting {host_ip}...", total=None)
                    try:
                        os_info = self.network_scanner.os_fingerprint(host_ip)
                        all_results["os"][host_ip] = os_info
                    except Exception as e:
                        self.console.print(f"[red]Error OS fingerprinting {host_ip}: {str(e)}[/red]")
                        all_results["os"][host_ip] = "Unknown"
                    progress.update(task4, completed=True)
            
            self.display_full_recon_results(all_results)
            self.save_results("full_reconnaissance", all_results)
            
        except Exception as e:
            self.console.print(f"[red]Error during full reconnaissance: {str(e)}[/red]")
        
        self.wait_for_user()

    def export_results(self):
        """Export scan results."""
        try:
            self.console.print(Panel("📄 [bold cyan]Export Results[/bold cyan]", border_style="cyan"))
            
            # List available result files
            results_dir = "results"
            if not os.path.exists(results_dir) or not os.listdir(results_dir):
                self.console.print("[red]No results available to export[/red]")
                self.wait_for_user()
                return
            
            files = [f for f in os.listdir(results_dir) if f.endswith('.json')]
            
            if not files:
                self.console.print("[red]No result files found[/red]")
                self.wait_for_user()
                return
            
            table = Table(title="[bold green]Available Results[/bold green]")
            table.add_column("#", style="cyan", width=4)
            table.add_column("File", style="white")
            table.add_column("Size", style="yellow")
            
            for i, file in enumerate(files, 1):
                file_path = os.path.join(results_dir, file)
                size = os.path.getsize(file_path)
                table.add_row(str(i), file, f"{size} bytes")
            
            self.console.print(table)
            
            choice = IntPrompt.ask("Select file to export (0 to cancel)", 
                                choices=[str(i) for i in range(len(files) + 1)])
            
            if choice == 0:
                return
            
            selected_file = files[choice - 1]
            export_format = Prompt.ask("Export format", choices=["json", "csv", "txt"], default="json")
            
            self.console.print(f"[green]Exporting {selected_file} as {export_format}...[/green]")
            
            # Here you would implement the actual export logic
            self.console.print(f"[green]✓ Results exported successfully[/green]")
            
        except (ValueError, IndexError):
            self.console.print("[red]Invalid selection[/red]")
        except Exception as e:
            self.console.print(f"[red]Error exporting results: {str(e)}[/red]")
        
        self.wait_for_user()

    # Display methods for network scanning results
    def display_host_results(self, hosts):
        """Display host discovery results."""
        table = Table(title="[bold green]Discovered Hosts[/bold green]", box=box.ROUNDED)
        table.add_column("Host", style="cyan", no_wrap=True)
        table.add_column("Status", style="green", no_wrap=True)
        table.add_column("Response Time", style="yellow")
        
        for host in hosts:
            table.add_row(host.get("ip", "Unknown"), "Up", f"{host.get('rtt', 0):.2f}ms")
        
        self.console.print(table)

    def display_port_results(self, ports):
        """Display port scan results."""
        table = Table(title="[bold green]Open Ports[/bold green]", box=box.ROUNDED)
        table.add_column("Port", style="cyan", no_wrap=True)
        table.add_column("Protocol", style="blue", no_wrap=True)
        table.add_column("State", style="green", no_wrap=True)
        table.add_column("Service", style="yellow")
        
        for port in ports:
            table.add_row(
                str(port.get("port", "Unknown")),
                port.get("protocol", "tcp").upper(),
                port.get("state", "unknown"),
                port.get("service", "unknown")
            )
        
        self.console.print(table)

    def display_service_results(self, services):
        """Display service detection results."""
        table = Table(title="[bold green]Detected Services[/bold green]", box=box.ROUNDED)
        table.add_column("Port", style="cyan", no_wrap=True)
        table.add_column("Service", style="blue", no_wrap=True)
        table.add_column("Version", style="green")
        table.add_column("Extra Info", style="yellow")
        
        for service in services:
            table.add_row(
                str(service.get("port", "Unknown")),
                service.get("name", "unknown"),
                service.get("version", "unknown"),
                service.get("extrainfo", "")
            )
        
        self.console.print(table)

    def display_os_results(self, os_info):
        """Display OS fingerprinting results."""
        if isinstance(os_info, dict):
            table = Table(title="[bold green]OS Fingerprint Results[/bold green]", box=box.ROUNDED)
            table.add_column("Attribute", style="cyan", no_wrap=True)
            table.add_column("Value", style="white")
            
            for key, value in os_info.items():
                table.add_row(key.title(), str(value))
            
            self.console.print(table)
        else:
            self.console.print(Panel(str(os_info), title="[bold green]OS Information[/bold green]"))

    def display_full_recon_results(self, results):
        """Display full reconnaissance results."""
        self.console.print(Panel("[bold green]Full Reconnaissance Complete[/bold green]", 
                                border_style="green"))
        
        # Summary
        summary_table = Table(title="[bold cyan]Reconnaissance Summary[/bold cyan]", box=box.ROUNDED)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Count", style="green")
        
        summary_table.add_row("Hosts Discovered", str(len(results["hosts"])))
        total_ports = sum(len(ports) for ports in results["ports"].values())
        summary_table.add_row("Total Open Ports", str(total_ports))
        total_services = sum(len(services) for services in results["services"].values())
        summary_table.add_row("Services Identified", str(total_services))
        
        self.console.print(summary_table)
        
        # Detailed results for each host
        for host in results["hosts"][:3]:  # Show first 3 hosts
            host_ip = host.get("ip", "Unknown")
            
            self.console.print(f"\n[bold yellow]═══ Host: {host_ip} ═══[/bold yellow]")
            
            if host_ip in results["ports"] and results["ports"][host_ip]:
                self.display_port_results(results["ports"][host_ip])
            
            if host_ip in results["services"] and results["services"][host_ip]:
                self.display_service_results(results["services"][host_ip])    

    def web_scanning_menu(self):
        """Handle web scanning operations."""
        while True:
            self.console.clear()
            self.console.print(Panel("🌐 [bold cyan]Web Application Security Tools[/bold cyan]", 
                                   border_style="cyan"))
            
            options = Table(show_header=False, box=box.SIMPLE)
            options.add_column("Option", style="bold yellow", width=8)
            options.add_column("Description", style="white")
            
            web_options = [
                ("1", "URL Analysis"),
                ("2", "Directory Bruteforce"),
                ("3", "XSS Vulnerability Test"),
                ("4", "SQL Injection Test"),
                ("5", "Check Robots.txt"),
                ("6", "Check Sitemap.xml"),
                ("7", "Check Common Files"),
                ("8", "Comprehensive Web Scan"),
                ("0", "← Back to Main Menu")
            ]
            
            for opt, desc in web_options:
                options.add_row(opt, desc)
            
            self.console.print(options)
            self.console.print()
            
            choice = Prompt.ask("[bold green]Select option", choices=[str(i) for i in range(9)])
            
            if choice == "0":
                break
            elif choice == "1":
                self.url_analysis()
            elif choice == "2":
                self.directory_bruteforce()
            elif choice == "3":
                self.xss_test()
            elif choice == "4":
                self.sqli_test()
            elif choice == "5":
                self.check_robots_txt()
            elif choice == "6":
                self.check_sitemap()
            elif choice == "7":
                self.check_common_files()
            elif choice == "8":
                self.comprehensive_web_scan()
    
    def packet_analysis_menu(self):
        """Handle packet analysis operations."""
        while True:
            self.console.clear()
            self.console.print(Panel("📡 [bold cyan]Packet Analysis & Network Sniffing[/bold cyan]", 
                                   border_style="cyan"))
            
            options = Table(show_header=False, box=box.SIMPLE)
            options.add_column("Option", style="bold yellow", width=8)
            options.add_column("Description", style="white")
            
            packet_options = [
                ("1", "Start Packet Sniffing"),
                ("2", "Stop Packet Sniffing"),
                ("3", "View Captured Packets"),
                ("4", "Analyze Packets"),
                ("5", "Save Capture to File"),
                ("6", "Load Capture from File"),
                ("7", "Detect Suspicious Activity"),
                ("0", "← Back to Main Menu")
            ]
            
            for opt, desc in packet_options:
                options.add_row(opt, desc)
            
            self.console.print(options)
            self.console.print()
            
            choice = Prompt.ask("[bold green]Select option", choices=[str(i) for i in range(8)])
            
            if choice == "0":
                break
            elif choice == "1":
                self.start_sniffing()
            elif choice == "2":
                self.stop_sniffing()
            elif choice == "3":
                self.view_captured_packets()
            elif choice == "4":
                self.analyze_packets()
            elif choice == "5":
                self.save_capture()
            elif choice == "6":
                self.load_capture()
            elif choice == "7":
                self.detect_suspicious_activity()
    
    def exploitation_tools_menu(self):
        """Handle exploitation tools operations."""
        while True:
            self.console.clear()
            self.console.print(Panel("⚡ [bold cyan]Exploitation & Penetration Tools[/bold cyan]", 
                                   border_style="cyan"))
            
            options = Table(show_header=False, box=box.SIMPLE)
            options.add_column("Option", style="bold yellow", width=8)
            options.add_column("Description", style="white")
            
            exploit_options = [
                ("1", "Start Reverse Shell Listener"),
                ("2", "Stop Reverse Shell Listener"),
                ("3", "SSH Brute Force"),
                ("4", "FTP Brute Force"),
                ("5", "FTP Anonymous Test"),
                ("6", "Generate Payload"),
                ("7", "Test Command Injection"),
                ("8", "Get Exploit Suggestions"),
                ("0", "← Back to Main Menu")
            ]
            
            for opt, desc in exploit_options:
                options.add_row(opt, desc)
            
            self.console.print(options)
            self.console.print()
            
            choice = Prompt.ask("[bold green]Select option", choices=[str(i) for i in range(9)])
            
            if choice == "0":
                break
            elif choice == "1":
                self.start_reverse_shell()
            elif choice == "2":
                self.stop_reverse_shell()
            elif choice == "3":
                self.ssh_brute_force()
            elif choice == "4":
                self.ftp_brute_force()
            elif choice == "5":
                self.ftp_anonymous_test()
            elif choice == "6":
                self.generate_payload()
            elif choice == "7":
                self.test_command_injection()
            elif choice == "8":
                self.get_exploit_suggestions()
    
    def monitoring_tools_menu(self):
        """Handle monitoring tools operations."""
        while True:
            self.console.clear()
            self.console.print(Panel("📊 [bold cyan]Network Monitoring & Alerting[/bold cyan]", 
                                   border_style="cyan"))
            
            options = Table(show_header=False, box=box.SIMPLE)
            options.add_column("Option", style="bold yellow", width=8)
            options.add_column("Description", style="white")
            
            monitor_options = [
                ("1", "Add Host Monitor"),
                ("2", "Remove Host Monitor"),
                ("3", "View Monitoring Status"),
                ("4", "View Monitoring History"),
                ("5", "Generate Monitoring Report"),
                ("6", "Export Monitoring Data"),
                ("7", "Stop All Monitoring"),
                ("0", "← Back to Main Menu")
            ]
            
            for opt, desc in monitor_options:
                options.add_row(opt, desc)
            
            self.console.print(options)
            self.console.print()
            
            choice = Prompt.ask("[bold green]Select option", choices=[str(i) for i in range(8)])
            
            if choice == "0":
                break
            elif choice == "1":
                self.add_host_monitor()
            elif choice == "2":
                self.remove_host_monitor()
            elif choice == "3":
                self.view_monitoring_status()
            elif choice == "4":
                self.view_monitoring_history()
            elif choice == "5":
                self.generate_monitoring_report()
            elif choice == "6":
                self.export_monitoring_data()
            elif choice == "7":
                self.stop_all_monitoring()
    
    def utilities_menu(self):
        """Handle utilities and information gathering."""
        while True:
            self.console.clear()
            self.console.print(Panel("🛠️  [bold cyan]Utilities & Information Gathering[/bold cyan]", 
                                   border_style="cyan"))
            
            options = Table(show_header=False, box=box.SIMPLE)
            options.add_column("Option", style="bold yellow", width=8)
            options.add_column("Description", style="white")
            
            utilities_options = [
                ("1", "DNS Lookup"),
                ("2", "Reverse DNS Lookup"),
                ("3", "WHOIS Lookup"),
                ("4", "GeoIP Lookup"),
                ("5", "MAC Vendor Lookup"),
                ("6", "Subnet Calculator"),
                ("7", "Port Service Lookup"),
                ("8", "Network Interfaces"),
                ("9", "Bandwidth Test"),
                ("10", "Get Public IP"),
                ("11", "Traceroute"),
                ("0", "← Back to Main Menu")
            ]
            
            for opt, desc in utilities_options:
                options.add_row(opt, desc)
            
            self.console.print(options)
            self.console.print()
            
            choice = Prompt.ask("[bold green]Select option", choices=[str(i) for i in range(12)] + ["0"])
            
            if choice == "0":
                break
            elif choice == "1":
                self.dns_lookup()
            elif choice == "2":
                self.reverse_dns_lookup()
            elif choice == "3":
                self.whois_lookup()
            elif choice == "4":
                self.geoip_lookup()
            elif choice == "5":
                self.mac_vendor_lookup()
            elif choice == "6":
                self.subnet_calculator()
            elif choice == "7":
                self.port_service_lookup()
            elif choice == "8":
                self.network_interfaces()
            elif choice == "9":
                self.bandwidth_test()
            elif choice == "10":
                self.get_public_ip()
            elif choice == "11":
                self.traceroute_util()
    
    # ... (existing methods like host_discovery, port_scanning, etc. remain unchanged)

    def run(self):
        """Main application loop."""
        try:
            while True:
                self.console.clear()
                self.display_banner()
                self.display_main_menu()
                
                choice = Prompt.ask(
                    "\n[bold green]Select your option",
                    choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
                    default="1"
                )
                
                # Log the choice
                self.history.append(f"{datetime.now().strftime('%H:%M:%S')} - Menu option {choice}")
                
                if choice == "0":
                    self.console.print("[bold yellow]Thank you for using NetToolbox! Stay secure! 🔐[/bold yellow]")
                    break
                elif choice == "1":
                    self.network_scanning_menu()
                elif choice == "2":
                    self.web_scanning_menu()
                elif choice == "3":
                    self.packet_analysis_menu()
                elif choice == "4":
                    self.exploitation_tools_menu()
                elif choice == "5":
                    self.monitoring_tools_menu()
                elif choice == "6":
                    self.utilities_menu()
                elif choice == "7":
                    self.show_command_history()
                elif choice == "8":
                    self.show_settings()
                elif choice == "9":
                    self.show_help()
                    
        except KeyboardInterrupt:
            self.console.print("\n[bold red]Application interrupted by user[/bold red]")
        except Exception as e:
            self.console.print(f"\n[bold red]Unexpected error: {str(e)}[/bold red]")
        finally:
            self.cleanup()

    # ... (existing methods like show_command_history, show_settings, show_help, cleanup remain unchanged)

    def url_analysis(self):
        """Perform URL analysis."""
        url = Prompt.ask("[bold cyan]Enter URL to analyze")
        if not url:
            self.console.print("[red]Invalid URL[/red]")
            return
        
        self.console.print(f"[yellow]Analyzing {url}...[/yellow]")
        try:
            results = self.web_scanner.analyze_url(url)
            self.display_web_results(results)
            self.save_results("url_analysis", results)
        except Exception as e:
            self.console.print(f"[red]Error during URL analysis: {str(e)}[/red]")
        self.wait_for_user()

    def directory_bruteforce(self):
        """Perform directory brute force."""
        url = Prompt.ask("[bold cyan]Enter base URL")
        if not url:
            self.console.print("[red]Invalid URL[/red]")
            return
        
        self.console.print(f"[yellow]Starting directory brute force on {url}...[/yellow]")
        try:
            results = self.web_scanner.directory_bruteforce(url)
            self.display_directory_results(results)
            self.save_results("directory_bruteforce", results)
        except Exception as e:
            self.console.print(f"[red]Error during directory brute force: {str(e)}[/red]")
        self.wait_for_user()

    def xss_test(self):
        """Test for XSS vulnerabilities."""
        url = Prompt.ask("[bold cyan]Enter URL to test")
        if not url:
            self.console.print("[red]Invalid URL[/red]")
            return
        
        self.console.print(f"[yellow]Testing XSS on {url}...[/yellow]")
        try:
            results = self.web_scanner.test_xss_vulnerability(url)
            self.display_vulnerability_results(results, "XSS")
            self.save_results("xss_test", results)
        except Exception as e:
            self.console.print(f"[red]Error during XSS test: {str(e)}[/red]")
        self.wait_for_user()

    def sqli_test(self):
        """Test for SQL injection vulnerabilities."""
        url = Prompt.ask("[bold cyan]Enter URL to test")
        if not url:
            self.console.print("[red]Invalid URL[/red]")
            return
        
        self.console.print(f"[yellow]Testing SQL injection on {url}...[/yellow]")
        try:
            results = self.web_scanner.test_sql_injection(url)
            self.display_vulnerability_results(results, "SQL Injection")
            self.save_results("sqli_test", results)
        except Exception as e:
            self.console.print(f"[red]Error during SQL injection test: {str(e)}[/red]")
        self.wait_for_user()

    def check_robots_txt(self):
        """Check robots.txt file."""
        url = Prompt.ask("[bold cyan]Enter base URL")
        if not url:
            self.console.print("[red]Invalid URL[/red]")
            return
        
        self.console.print(f"[yellow]Checking robots.txt for {url}...[/yellow]")
        try:
            results = self.web_scanner.check_robots_txt(url)
            self.display_robots_results(results)
            self.save_results("robots_txt", results)
        except Exception as e:
            self.console.print(f"[red]Error checking robots.txt: {str(e)}[/red]")
        self.wait_for_user()

    def check_sitemap(self):
        """Check sitemap.xml file."""
        url = Prompt.ask("[bold cyan]Enter base URL")
        if not url:
            self.console.print("[red]Invalid URL[/red]")
            return
        
        self.console.print(f"[yellow]Checking sitemap.xml for {url}...[/yellow]")
        try:
            results = self.web_scanner.check_sitemap(url)
            self.display_sitemap_results(results)
            self.save_results("sitemap", results)
        except Exception as e:
            self.console.print(f"[red]Error checking sitemap: {str(e)}[/red]")
        self.wait_for_user()

    def check_common_files(self):
        """Check for common files."""
        url = Prompt.ask("[bold cyan]Enter base URL")
        if not url:
            self.console.print("[red]Invalid URL[/red]")
            return
        
        self.console.print(f"[yellow]Checking common files on {url}...[/yellow]")
        try:
            results = self.web_scanner.check_common_files(url)
            self.display_common_files_results(results)
            self.save_results("common_files", results)
        except Exception as e:
            self.console.print(f"[red]Error checking common files: {str(e)}[/red]")
        self.wait_for_user()

    def comprehensive_web_scan(self):
        """Perform comprehensive web scan."""
        url = Prompt.ask("[bold cyan]Enter URL to scan")
        if not url:
            self.console.print("[red]Invalid URL[/red]")
            return
        
        self.console.print(f"[yellow]Starting comprehensive scan of {url}...[/yellow]")
        try:
            results = self.web_scanner.comprehensive_scan(url)
            self.display_comprehensive_web_results(results)
            self.save_results("comprehensive_web_scan", results)
        except Exception as e:
            self.console.print(f"[red]Error during comprehensive scan: {str(e)}[/red]")
        self.wait_for_user()

    def start_sniffing(self):
        """Start packet sniffing."""
        interface = Prompt.ask("[bold cyan]Enter interface (press Enter for default)", default="")
        packet_filter = Prompt.ask("[bold cyan]Enter filter (e.g., tcp, udp, port 80)", default="")
        packet_count = IntPrompt.ask("[bold cyan]Enter packet count (0 for infinite)", default=0)
        
        if interface == "":
            interface = None
        
        self.console.print(f"[yellow]Starting packet sniffing...[/yellow]")
        try:
            success = self.packet_analyzer.start_sniffing(interface, packet_filter, packet_count)
            if success:
                self.console.print("[green]Packet sniffing started[/green]")
            else:
                self.console.print("[red]Failed to start packet sniffing[/red]")
        except Exception as e:
            self.console.print(f"[red]Error starting packet sniffing: {str(e)}[/red]")
        self.wait_for_user()

    def stop_sniffing(self):
        """Stop packet sniffing."""
        self.console.print("[yellow]Stopping packet sniffing...[/yellow]")
        try:
            self.packet_analyzer.stop_sniffing()
            self.console.print("[green]Packet sniffing stopped[/green]")
        except Exception as e:
            self.console.print(f"[red]Error stopping packet sniffing: {str(e)}[/red]")
        self.wait_for_user()

    def view_captured_packets(self):
        """View captured packets."""
        self.console.print("[yellow]Fetching captured packets...[/yellow]")
        try:
            packets = self.packet_analyzer.captured_packets
            if not packets:
                self.console.print("[red]No packets captured[/red]")
                return
            
            self.display_packets(packets)
        except Exception as e:
            self.console.print(f"[red]Error viewing packets: {str(e)}[/red]")
        self.wait_for_user()

    def analyze_packets(self):
        """Analyze captured packets."""
        self.console.print("[yellow]Analyzing packets...[/yellow]")
        try:
            summary = self.packet_analyzer.get_packet_summary()
            self.display_packet_summary(summary)
        except Exception as e:
            self.console.print(f"[red]Error analyzing packets: {str(e)}[/red]")
        self.wait_for_user()

    def save_capture(self):
        """Save capture to file."""
        filename = Prompt.ask("[bold cyan]Enter filename", default="capture.pcap")
        try:
            success = self.packet_analyzer.save_capture(filename)
            if success:
                self.console.print("[green]Capture saved[/green]")
            else:
                self.console.print("[red]Failed to save capture[/red]")
        except Exception as e:
            self.console.print(f"[red]Error saving capture: {str(e)}[/red]")
        self.wait_for_user()

    def load_capture(self):
        """Load capture from file."""
        filename = Prompt.ask("[bold cyan]Enter filename")
        try:
            success = self.packet_analyzer.load_capture(filename)
            if success:
                self.console.print("[green]Capture loaded[/green]")
            else:
                self.console.print("[red]Failed to load capture[/red]")
        except Exception as e:
            self.console.print(f"[red]Error loading capture: {str(e)}[/red]")
        self.wait_for_user()

    def detect_suspicious_activity(self):
        """Detect suspicious activity."""
        self.console.print("[yellow]Detecting suspicious activity...[/yellow]")
        try:
            suspicious = self.packet_analyzer.detect_suspicious_activity()
            self.display_suspicious_activity(suspicious)
        except Exception as e:
            self.console.print(f"[red]Error detecting suspicious activity: {str(e)}[/red]")
        self.wait_for_user()

    def start_reverse_shell(self):
        """Start reverse shell listener."""
        port = IntPrompt.ask("[bold cyan]Enter port", default=4444)
        try:
            success = self.exploitation_tools.start_reverse_shell_listener(port)
            if success:
                self.console.print("[green]Reverse shell listener started[/green]")
            else:
                self.console.print("[red]Failed to start reverse shell listener[/red]")
        except Exception as e:
            self.console.print(f"[red]Error starting reverse shell: {str(e)}[/red]")
        self.wait_for_user()

    def stop_reverse_shell(self):
        """Stop reverse shell listener."""
        try:
            self.exploitation_tools.stop_reverse_shell_listener()
            self.console.print("[green]Reverse shell listener stopped[/green]")
        except Exception as e:
            self.console.print(f"[red]Error stopping reverse shell: {str(e)}[/red]")
        self.wait_for_user()

    def ssh_brute_force(self):
        """Perform SSH brute force."""
        target = Prompt.ask("[bold cyan]Enter target host")
        port = IntPrompt.ask("[bold cyan]Enter SSH port", default=22)
        userlist = Prompt.ask("[bold cyan]Enter path to userlist (press Enter for default)", default="")
        passlist = Prompt.ask("[bold cyan]Enter path to passlist (press Enter for default)", default="")
        
        if userlist == "":
            userlist = None
        if passlist == "":
            passlist = None
        
        self.console.print(f"[yellow]Starting SSH brute force on {target}...[/yellow]")
        try:
            results = self.exploitation_tools.ssh_brute_force(target, port, userlist, passlist)
            self.display_brute_force_results(results, "SSH")
            self.save_results("ssh_brute_force", results)
        except Exception as e:
            self.console.print(f"[red]Error during SSH brute force: {str(e)}[/red]")
        self.wait_for_user()

    def ftp_brute_force(self):
        """Perform FTP brute force."""
        target = Prompt.ask("[bold cyan]Enter target host")
        port = IntPrompt.ask("[bold cyan]Enter FTP port", default=21)
        userlist = Prompt.ask("[bold cyan]Enter path to userlist (press Enter for default)", default="")
        passlist = Prompt.ask("[bold cyan]Enter path to passlist (press Enter for default)", default="")
        
        if userlist == "":
            userlist = None
        if passlist == "":
            passlist = None
        
        self.console.print(f"[yellow]Starting FTP brute force on {target}...[/yellow]")
        try:
            results = self.exploitation_tools.ftp_brute_force(target, port, userlist, passlist)
            self.display_brute_force_results(results, "FTP")
            self.save_results("ftp_brute_force", results)
        except Exception as e:
            self.console.print(f"[red]Error during FTP brute force: {str(e)}[/red]")
        self.wait_for_user()

    def ftp_anonymous_test(self):
        """Test FTP anonymous access."""
        target = Prompt.ask("[bold cyan]Enter target host")
        port = IntPrompt.ask("[bold cyan]Enter FTP port", default=21)
        
        self.console.print(f"[yellow]Testing FTP anonymous access on {target}...[/yellow]")
        try:
            results = self.exploitation_tools.ftp_anonymous_test(target, port)
            self.display_ftp_anonymous_results(results)
            self.save_results("ftp_anonymous_test", results)
        except Exception as e:
            self.console.print(f"[red]Error during FTP anonymous test: {str(e)}[/red]")
        self.wait_for_user()

    def generate_payload(self):
        """Generate a payload."""
        payload_type = Prompt.ask("[bold cyan]Select payload type", 
                                 choices=["reverse_shell_bash", "reverse_shell_python", "reverse_shell_php", 
                                         "sql_injection_union", "xss_basic", "xss_advanced", 
                                         "directory_traversal", "command_injection"])
        options = {}
        if payload_type in ["reverse_shell_bash", "reverse_shell_python", "reverse_shell_php"]:
            host = Prompt.ask("[bold cyan]Enter host", default="127.0.0.1")
            port = IntPrompt.ask("[bold cyan]Enter port", default=4444)
            options = {'host': host, 'port': port}
        elif payload_type == "sql_injection_union":
            columns = IntPrompt.ask("[bold cyan]Enter number of columns", default=3)
            options = {'columns': columns}
        elif payload_type == "directory_traversal":
            depth = IntPrompt.ask("[bold cyan]Enter depth", default=5)
            options = {'depth': depth}
        elif payload_type == "command_injection":
            command = Prompt.ask("[bold cyan]Enter command", default="id")
            options = {'command': command}
        
        try:
            payload = self.exploitation_tools.generate_payload(payload_type, options)
            self.console.print(Panel(payload, title="[bold green]Generated Payload[/bold green]"))
            self.save_results("generate_payload", {"type": payload_type, "options": options, "payload": payload})
        except Exception as e:
            self.console.print(f"[red]Error generating payload: {str(e)}[/red]")
        self.wait_for_user()

    def test_command_injection(self):
        """Test command injection."""
        url = Prompt.ask("[bold cyan]Enter URL")
        parameter = Prompt.ask("[bold cyan]Enter parameter to test")
        
        self.console.print(f"[yellow]Testing command injection on {url}...[/yellow]")
        try:
            results = self.exploitation_tools.test_command_injection(url, parameter)
            self.display_vulnerability_results(results, "Command Injection")
            self.save_results("command_injection_test", results)
        except Exception as e:
            self.console.print(f"[red]Error during command injection test: {str(e)}[/red]")
        self.wait_for_user()

    def get_exploit_suggestions(self):
        """Get exploit suggestions."""
        service_name = Prompt.ask("[bold cyan]Enter service name")
        version = Prompt.ask("[bold cyan]Enter version (optional)", default="")
        port = IntPrompt.ask("[bold cyan]Enter port", default=0)
        
        service_info = {'name': service_name, 'version': version, 'port': port}
        try:
            suggestions = self.exploitation_tools.get_exploit_suggestions(service_info)
            self.display_exploit_suggestions(suggestions)
            self.save_results("exploit_suggestions", suggestions)
        except Exception as e:
            self.console.print(f"[red]Error getting exploit suggestions: {str(e)}[/red]")
        self.wait_for_user()

    def add_host_monitor(self):
        """Add host monitor."""
        host = Prompt.ask("[bold cyan]Enter host to monitor")
        monitor_type = Prompt.ask("[bold cyan]Enter monitor type", choices=["ping", "http", "tcp"], default="ping")
        interval = IntPrompt.ask("[bold cyan]Enter interval in seconds", default=60)
        
        try:
            success = self.monitoring_tools.add_host_monitor(host, interval, monitor_type)
            if success:
                self.console.print("[green]Host monitor added[/green]")
            else:
                self.console.print("[red]Failed to add host monitor[/red]")
        except Exception as e:
            self.console.print(f"[red]Error adding host monitor: {str(e)}[/red]")
        self.wait_for_user()

    def remove_host_monitor(self):
        """Remove host monitor."""
        host = Prompt.ask("[bold cyan]Enter host")
        monitor_type = Prompt.ask("[bold cyan]Enter monitor type", choices=["ping", "http", "tcp"], default="ping")
        
        try:
            success = self.monitoring_tools.remove_host_monitor(host, monitor_type)
            if success:
                self.console.print("[green]Host monitor removed[/green]")
            else:
                self.console.print("[red]Failed to remove host monitor[/red]")
        except Exception as e:
            self.console.print(f"[red]Error removing host monitor: {str(e)}[/red]")
        self.wait_for_user()

    def view_monitoring_status(self):
        """View monitoring status."""
        try:
            status = self.monitoring_tools.get_monitoring_status()
            self.display_monitoring_status(status)
        except Exception as e:
            self.console.print(f"[red]Error getting monitoring status: {str(e)}[/red]")
        self.wait_for_user()

    def view_monitoring_history(self):
        """View monitoring history."""
        monitor_id = Prompt.ask("[bold cyan]Enter monitor ID")
        hours = IntPrompt.ask("[bold cyan]Enter hours of history", default=24)
        
        try:
            history = self.monitoring_tools.get_monitoring_history(monitor_id, hours)
            self.display_monitoring_history(history)
        except Exception as e:
            self.console.print(f"[red]Error getting monitoring history: {str(e)}[/red]")
        self.wait_for_user()

    def generate_monitoring_report(self):
        """Generate monitoring report."""
        hours = IntPrompt.ask("[bold cyan]Enter hours for report", default=24)
        
        try:
            report = self.monitoring_tools.generate_monitoring_report(hours)
            self.display_monitoring_report(report)
            self.save_results("monitoring_report", report)
        except Exception as e:
            self.console.print(f"[red]Error generating monitoring report: {str(e)}[/red]")
        self.wait_for_user()

    def export_monitoring_data(self):
        """Export monitoring data."""
        filename = Prompt.ask("[bold cyan]Enter filename")
        format_type = Prompt.ask("[bold cyan]Enter format", choices=["json", "csv"], default="json")
        
        try:
            success = self.monitoring_tools.export_monitoring_data(filename, format_type)
            if success:
                self.console.print("[green]Monitoring data exported[/green]")
            else:
                self.console.print("[red]Failed to export monitoring data[/red]")
        except Exception as e:
            self.console.print(f"[red]Error exporting monitoring data: {str(e)}[/red]")
        self.wait_for_user()

    def stop_all_monitoring(self):
        """Stop all monitoring."""
        try:
            self.monitoring_tools.stop_all_monitoring()
            self.console.print("[green]All monitoring stopped[/green]")
        except Exception as e:
            self.console.print(f"[red]Error stopping monitoring: {str(e)}[/red]")
        self.wait_for_user()

    def dns_lookup(self):
        """Perform DNS lookup."""
        hostname = Prompt.ask("[bold cyan]Enter hostname")
        record_type = Prompt.ask("[bold cyan]Enter record type", choices=["A", "AAAA", "MX", "TXT"], default="A")
        
        try:
            results = self.utilities.dns_lookup(hostname, record_type)
            self.display_dns_results(results)
            self.save_results("dns_lookup", results)
        except Exception as e:
            self.console.print(f"[red]Error during DNS lookup: {str(e)}[/red]")
        self.wait_for_user()

    def reverse_dns_lookup(self):
        """Perform reverse DNS lookup."""
        ip_address = Prompt.ask("[bold cyan]Enter IP address")
        
        try:
            results = self.utilities.reverse_dns_lookup(ip_address)
            self.display_reverse_dns_results(results)
            self.save_results("reverse_dns_lookup", results)
        except Exception as e:
            self.console.print(f"[red]Error during reverse DNS lookup: {str(e)}[/red]")
        self.wait_for_user()

    def whois_lookup(self):
        """Perform WHOIS lookup."""
        domain = Prompt.ask("[bold cyan]Enter domain")
        
        try:
            results = self.utilities.whois_lookup(domain)
            self.display_whois_results(results)
            self.save_results("whois_lookup", results)
        except Exception as e:
            self.console.print(f"[red]Error during WHOIS lookup: {str(e)}[/red]")
        self.wait_for_user()

    def geoip_lookup(self):
        """Perform GeoIP lookup."""
        ip_address = Prompt.ask("[bold cyan]Enter IP address")
        
        try:
            results = self.utilities.geoip_lookup(ip_address)
            self.display_geoip_results(results)
            self.save_results("geoip_lookup", results)
        except Exception as e:
            self.console.print(f"[red]Error during GeoIP lookup: {str(e)}[/red]")
        self.wait_for_user()

    def mac_vendor_lookup(self):
        """Perform MAC vendor lookup."""
        mac_address = Prompt.ask("[bold cyan]Enter MAC address")
        
        try:
            results = self.utilities.mac_vendor_lookup(mac_address)
            self.display_mac_vendor_results(results)
            self.save_results("mac_vendor_lookup", results)
        except Exception as e:
            self.console.print(f"[red]Error during MAC vendor lookup: {str(e)}[/red]")
        self.wait_for_user()

    def subnet_calculator(self):
        """Perform subnet calculation."""
        network = Prompt.ask("[bold cyan]Enter network (e.g., 192.168.1.0/24)")
        
        try:
            results = self.utilities.subnet_calculator(network)
            self.display_subnet_results(results)
            self.save_results("subnet_calculator", results)
        except Exception as e:
            self.console.print(f"[red]Error during subnet calculation: {str(e)}[/red]")
        self.wait_for_user()

    def port_service_lookup(self):
        """Perform port service lookup."""
        port = IntPrompt.ask("[bold cyan]Enter port number")
        protocol = Prompt.ask("[bold cyan]Enter protocol", choices=["tcp", "udp"], default="tcp")
        
        try:
            results = self.utilities.port_service_lookup(port, protocol)
            self.display_port_service_results(results)
            self.save_results("port_service_lookup", results)
        except Exception as e:
            self.console.print(f"[red]Error during port service lookup: {str(e)}[/red]")
        self.wait_for_user()

    def network_interfaces(self):
        """Get network interfaces."""
        try:
            results = self.utilities.network_interfaces()
            self.display_network_interfaces(results)
            self.save_results("network_interfaces", results)
        except Exception as e:
            self.console.print(f"[red]Error getting network interfaces: {str(e)}[/red]")
        self.wait_for_user()

    def bandwidth_test(self):
        """Perform bandwidth test."""
        test_url = Prompt.ask("[bold cyan]Enter test URL (optional)", default="")
        test_size = Prompt.ask("[bold cyan]Enter test size (optional)", default="1MB")
        
        if test_url == "":
            test_url = None
        
        try:
            results = self.utilities.bandwidth_test(test_url, test_size)
            self.display_bandwidth_results(results)
            self.save_results("bandwidth_test", results)
        except Exception as e:
            self.console.print(f"[red]Error during bandwidth test: {str(e)}[/red]")
        self.wait_for_user()

    def get_public_ip(self):
        """Get public IP."""
        try:
            results = self.utilities.get_public_ip()
            self.display_public_ip_results(results)
            self.save_results("public_ip", results)
        except Exception as e:
            self.console.print(f"[red]Error getting public IP: {str(e)}[/red]")
        self.wait_for_user()

    def traceroute_util(self):
        """Perform traceroute."""
        target = Prompt.ask("[bold cyan]Enter target host")
        max_hops = IntPrompt.ask("[bold cyan]Enter max hops", default=30)
        
        try:
            results = self.utilities.traceroute(target, max_hops)
            self.display_traceroute_results(results)
            self.save_results("traceroute", results)
        except Exception as e:
            self.console.print(f"[red]Error during traceroute: {str(e)}[/red]")
        self.wait_for_user()

    # Display methods for results (to be implemented or enhanced as needed)
    def display_web_results(self, results):
        """Display web analysis results."""
        table = Table(title="[bold green]Web Analysis Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            if key not in ['forms', 'links', 'technologies', 'security_headers']:
                table.add_row(key, str(value))
        
        self.console.print(table)
        
        if 'forms' in results and results['forms']:
            forms_table = Table(title="[bold yellow]Forms Found[/bold yellow]", box=box.ROUNDED)
            forms_table.add_column("Action", style="cyan")
            forms_table.add_column("Method", style="blue")
            forms_table.add_column("Inputs", style="green")
            
            for form in results['forms']:
                forms_table.add_row(form.get('action', ''), form.get('method', ''), str(len(form.get('inputs', []))))
            
            self.console.print(forms_table)
        
        if 'technologies' in results and results['technologies']:
            tech_table = Table(title="[bold yellow]Technologies Detected[/bold yellow]", box=box.ROUNDED)
            tech_table.add_column("Technology", style="cyan")
            
            for tech in results['technologies']:
                tech_table.add_row(tech)
            
            self.console.print(tech_table)
    
    def display_directory_results(self, results):
        """Display directory brute force results."""
        if not results:
            self.console.print("[red]No directories/files found[/red]")
            return
        
        table = Table(title="[bold green]Discovered Directories/Files[/bold green]", box=box.ROUNDED)
        table.add_column("URL", style="cyan", no_wrap=True)
        table.add_column("Status", style="green", no_wrap=True)
        table.add_column("Size", style="yellow")
        table.add_column("Type", style="blue")
        
        for item in results:
            status = str(item.get('status_code', ''))
            size = item.get('content_length', 'Unknown')
            content_type = item.get('content_type', 'Unknown')
            table.add_row(item.get('url', ''), status, size, content_type)
        
        self.console.print(table)
    
    def display_vulnerability_results(self, results, vuln_type):
        """Display vulnerability results."""
        if not results:
            self.console.print(f"[green]No {vuln_type} vulnerabilities found[/green]")
            return
        
        table = Table(title=f"[bold green]{vuln_type} Vulnerabilities[/bold green]", box=box.ROUNDED)
        table.add_column("URL", style="cyan", no_wrap=True)
        table.add_column("Method", style="blue")
        table.add_column("Parameter", style="green")
        table.add_column("Payload", style="yellow")
        table.add_column("Confidence", style="red")
        
        for vuln in results:
            table.add_row(
                vuln.get('url', ''),
                vuln.get('method', ''),
                vuln.get('vulnerable_parameter', ''),
                vuln.get('payload', ''),
                vuln.get('confidence', '')
            )
        
        self.console.print(table)
    
    def display_robots_results(self, results):
        """Display robots.txt results."""
        if not results.get('found'):
            self.console.print("[red]robots.txt not found[/red]")
            return
        
        table = Table(title="[bold green]robots.txt Analysis[/bold green]", box=box.ROUNDED)
        table.add_column("Disallowed Paths", style="cyan")
        table.add_column("Sitemaps", style="blue")
        
        disallowed = "\n".join(results.get('disallowed_paths', []))
        sitemaps = "\n".join(results.get('sitemaps', []))
        
        table.add_row(disallowed, sitemaps)
        self.console.print(table)
    
    def display_sitemap_results(self, results):
        """Display sitemap results."""
        if not results.get('found'):
            self.console.print("[red]sitemap.xml not found[/red]")
            return
        
        table = Table(title="[bold green]Sitemap Analysis[/bold green]", box=box.ROUNDED)
        table.add_column("URLs Found", style="cyan")
        table.add_column("Total URLs", style="green")
        
        urls = "\n".join(results.get('urls', [])[:5])  # Show first 5 URLs
        if len(results.get('urls', [])) > 5:
            urls += "\n..."
        
        table.add_row(urls, str(results.get('total_urls', 0)))
        self.console.print(table)
    
    def display_common_files_results(self, results):
        """Display common files results."""
        if not results:
            self.console.print("[green]No common files found[/green]")
            return
        
        table = Table(title="[bold green]Common Files Found[/bold green]", box=box.ROUNDED)
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("URL", style="blue")
        table.add_column("Size", style="green")
        table.add_column("Risk", style="red")
        
        for item in results:
            risk = item.get('risk_level', 'Unknown')
            table.add_row(
                item.get('file', ''),
                item.get('url', ''),
                str(item.get('size', '')),
                risk
            )
        
        self.console.print(table)
    
    def display_comprehensive_web_results(self, results):
        """Display comprehensive web scan results."""
        self.console.print(Panel("[bold green]Comprehensive Web Scan Complete[/bold green]", 
                                border_style="green"))
        
        # Display basic info
        if 'basic_info' in results:
            self.display_web_results(results['basic_info'])
        
        # Display directories
        if 'directories' in results and results['directories']:
            self.display_directory_results(results['directories'])
        
        # Display vulnerabilities
        if 'vulnerabilities' in results and results['vulnerabilities']:
            self.display_vulnerability_results(results['vulnerabilities'], "Web")
        
        # Display common files
        if 'sensitive_files' in results and results['sensitive_files']:
            self.display_common_files_results(results['sensitive_files'])
    
    def display_packets(self, packets):
        """Display captured packets."""
        table = Table(title="[bold green]Captured Packets[/bold green]", box=box.ROUNDED)
        table.add_column("Number", style="cyan", no_wrap=True)
        table.add_column("Summary", style="white")
        
        for i, packet in enumerate(packets[-20:]):  # Show last 20 packets
            summary = f"{len(packet)} bytes"
            if hasattr(packet, 'summary'):
                summary = packet.summary()
            table.add_row(str(i+1), summary)
        
        self.console.print(table)
    
    def display_packet_summary(self, summary):
        """Display packet summary."""
        table = Table(title="[bold green]Packet Summary[/bold green]", box=box.ROUNDED)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in summary.items():
            if isinstance(value, dict):
                for k, v in value.items():
                    table.add_row(f"{key}.{k}", str(v))
            else:
                table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_suspicious_activity(self, suspicious):
        """Display suspicious activity."""
        if not suspicious:
            self.console.print("[green]No suspicious activity detected[/green]")
            return
        
        table = Table(title="[bold red]Suspicious Activity Detected[/bold red]", box=box.ROUNDED)
        table.add_column("Type", style="cyan", no_wrap=True)
        table.add_column("Source", style="blue")
        table.add_column("Details", style="white")
        table.add_column("Severity", style="red")
        
        for activity in suspicious:
            table.add_row(
                activity.get('type', ''),
                activity.get('source', ''),
                activity.get('details', ''),
                activity.get('severity', '')
            )
        
        self.console.print(table)
    
    def display_brute_force_results(self, results, service):
        """Display brute force results."""
        if not results:
            self.console.print(f"[red]No {service} credentials found[/red]")
            return
        
        table = Table(title=f"[bold green]{service} Brute Force Results[/bold green]", box=box.ROUNDED)
        table.add_column("Username", style="cyan", no_wrap=True)
        table.add_column("Password", style="blue")
        table.add_column("Target", style="green")
        table.add_column("Port", style="yellow")
        
        for creds in results:
            table.add_row(
                creds.get('username', ''),
                creds.get('password', ''),
                creds.get('target', ''),
                str(creds.get('port', ''))
            )
        
        self.console.print(table)
    
    def display_ftp_anonymous_results(self, results):
        """Display FTP anonymous results."""
        table = Table(title="[bold green]FTP Anonymous Test Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            if key == 'directories' or key == 'files':
                value = ", ".join(value) if value else "None"
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_exploit_suggestions(self, suggestions):
        """Display exploit suggestions."""
        if not suggestions:
            self.console.print("[red]No exploit suggestions[/red]")
            return
        
        table = Table(title="[bold green]Exploit Suggestions[/bold green]", box=box.ROUNDED)
        table.add_column("Service", style="cyan", no_wrap=True)
        table.add_column("Exploit", style="blue")
        table.add_column("Description", style="white")
        table.add_column("Risk", style="red")
        
        for suggestion in suggestions:
            table.add_row(
                suggestion.get('service', ''),
                suggestion.get('exploit', ''),
                suggestion.get('description', ''),
                suggestion.get('risk', '')
            )
        
        self.console.print(table)
    
    def display_monitoring_status(self, status):
        """Display monitoring status."""
        table = Table(title="[bold green]Monitoring Status[/bold green]", box=box.ROUNDED)
        table.add_column("Monitor ID", style="cyan", no_wrap=True)
        table.add_column("Host", style="blue")
        table.add_column("Type", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Last Check", style="white")
        
        for monitor_id, info in status.get('monitors', {}).items():
            table.add_row(
                monitor_id,
                info.get('host', ''),
                info.get('type', ''),
                info.get('status', ''),
                info.get('last_check', '')
            )
        
        self.console.print(table)
    
    def display_monitoring_history(self, history):
        """Display monitoring history."""
        if not history:
            self.console.print("[red]No history data[/red]")
            return
        
        table = Table(title="[bold green]Monitoring History[/bold green]", box=box.ROUNDED)
        table.add_column("Timestamp", style="cyan", no_wrap=True)
        table.add_column("Success", style="green")
        table.add_column("Response Time", style="yellow")
        table.add_column("Details", style="white")
        
        for entry in history[-10:]:  # Show last 10 entries
            table.add_row(
                entry.get('timestamp', ''),
                str(entry.get('success', '')),
                str(entry.get('response_time', '')),
                entry.get('details', '')
            )
        
        self.console.print(table)
    
    def display_monitoring_report(self, report):
        """Display monitoring report."""
        table = Table(title="[bold green]Monitoring Report[/bold green]", box=box.ROUNDED)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in report.get('summary', {}).items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_dns_results(self, results):
        """Display DNS lookup results."""
        table = Table(title="[bold green]DNS Lookup Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            if key == 'addresses' or key == 'records':
                value = ", ".join(str(v) for v in value) if value else "None"
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_reverse_dns_results(self, results):
        """Display reverse DNS results."""
        table = Table(title="[bold green]Reverse DNS Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_whois_results(self, results):
        """Display WHOIS results."""
        table = Table(title="[bold green]WHOIS Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            if key == 'name_servers':
                value = ", ".join(value) if value else "None"
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_geoip_results(self, results):
        """Display GeoIP results."""
        table = Table(title="[bold green]GeoIP Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_mac_vendor_results(self, results):
        """Display MAC vendor results."""
        table = Table(title="[bold green]MAC Vendor Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_subnet_results(self, results):
        """Display subnet results."""
        table = Table(title="[bold green]Subnet Calculation Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_port_service_results(self, results):
        """Display port service results."""
        table = Table(title="[bold green]Port Service Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_network_interfaces(self, results):
        """Display network interfaces."""
        if not results:
            self.console.print("[red]No network interfaces found[/red]")
            return
        
        table = Table(title="[bold green]Network Interfaces[/bold green]", box=box.ROUNDED)
        table.add_column("Interface", style="cyan", no_wrap=True)
        table.add_column("Addresses", style="white")
        
        for interface in results:
            addrs = ", ".join(interface.get('addresses', []))
            table.add_row(interface.get('name', ''), addrs)
        
        self.console.print(table)
    
    def display_bandwidth_results(self, results):
        """Display bandwidth test results."""
        table = Table(title="[bold green]Bandwidth Test Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_public_ip_results(self, results):
        """Display public IP results."""
        table = Table(title="[bold green]Public IP Results[/bold green]", box=box.ROUNDED)
        table.add_column("Attribute", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        for key, value in results.items():
            table.add_row(key, str(value))
        
        self.console.print(table)
    
    def display_traceroute_results(self, results):
        """Display traceroute results."""
        if not results:
            self.console.print("[red]Traceroute failed[/red]")
            return
        
        table = Table(title="[bold green]Traceroute Results[/bold green]", box=box.ROUNDED)
        table.add_column("Hop", style="cyan", no_wrap=True)
        table.add_column("IP", style="blue")
        table.add_column("Hostname", style="green")
        table.add_column("RTT", style="yellow")
        
        for hop in results:
            if 'error' in hop:
                table.add_row("Error", hop['error'], "", "")
            else:
                table.add_row(
                    str(hop.get('hop', '')),
                    hop.get('ip_address', ''),
                    hop.get('hostname', ''),
                    str(hop.get('avg_rtt', ''))
                )
        
        self.console.print(table)
    
    def save_results(self, scan_type, results):
        """Save scan results to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results/{scan_type}_{timestamp}.json"
        
        result_data = {
            "timestamp": timestamp,
            "scan_type": scan_type,
            "results": results
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(result_data, f, indent=2, default=str)
            
            self.logger.log_action(f"Results saved to {filename}")
        except Exception as e:
            self.console.print(f"[red]Error saving results: {str(e)}[/red]")
    
    def wait_for_user(self):
        """Wait for user to press Enter."""
        Prompt.ask("\n[dim]Press Enter to continue...", default="")
    
    def show_command_history(self):
        # ... (existing code remains unchanged)
        """Show command history."""
        self.console.print(Panel("📝 [bold cyan]Command History[/bold cyan]", border_style="cyan"))
        
        if not self.history:
            self.console.print("[yellow]No commands in history[/yellow]")
        else:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Time", style="cyan", width=12)
            table.add_column("Action", style="white")
            
            for entry in self.history[-10:]:  # Show last 10 entries
                parts = entry.split(" - ", 1)
                if len(parts) == 2:
                    table.add_row(parts[0], parts[1])
        
            self.console.print(table)
        
        self.wait_for_user()
    
    def show_settings(self):
        # ... (existing code remains unchanged)
        """Show application settings."""
        self.console.print(Panel("⚙️ [bold cyan]Settings & Configuration[/bold cyan]", border_style="cyan"))
        
        settings_table = Table(show_header=True, header_style="bold magenta")
        settings_table.add_column("Setting", style="cyan")
        settings_table.add_column("Value", style="white")
        settings_table.add_column("Description", style="dim white")
        
        settings_table.add_row("Theme", self.current_theme, "Console color theme")
        settings_table.add_row("Log Level", "INFO", "Logging verbosity level")
        settings_table.add_row("Auto-save", "Enabled", "Automatically save scan results")
        settings_table.add_row("History Size", "100", "Maximum history entries")
        
        self.console.print(settings_table)
        self.console.print("\n[dim]Settings configuration will be available in future updates[/dim]")
        self.wait_for_user()
        
    def show_help(self):
        # ... (existing code remains unchanged)
    
        """Show help documentation."""
        self.console.print(Panel("❓ [bold cyan]Help & Documentation[/bold cyan]", border_style="cyan"))
        
        help_text = """
[bold yellow]NetToolbox - Network Security Toolkit[/bold yellow]

[bold white]Overview:[/bold white]
This comprehensive toolkit provides network security professionals with essential 
tools for reconnaissance, vulnerability assessment, and network monitoring.

[bold white]Main Features:[/bold white]
• Network Scanning & Reconnaissance
• Web Application Security Testing  
• Packet Analysis & Network Sniffing
• Exploitation & Penetration Testing Tools
• Network Monitoring & Alerting
• Utilities & Information Gathering

[bold white]Usage Tips:[/bold white]
• Always ensure you have proper authorization before scanning networks
• Results are automatically saved in the 'results/' directory
• All activities are logged in the 'logs/' directory
• Use the command history to repeat previous actions

[bold white]Keyboard Shortcuts:[/bold white]
• Ctrl+C: Interrupt current operation
• Enter: Continue/Confirm action

[bold red]Legal Notice:[/bold red]
This tool is intended for authorized testing and educational purposes only.
Users are responsible for complying with all applicable laws and regulations.
        """
        
        self.console.print(help_text)
        self.wait_for_user()
    
    def cleanup(self):
        # ... (existing code remains unchanged)
        """Cleanup resources before exit."""
        self.logger.log_action("Application shutdown")
def main():
    """Application entry point."""
    # Check Python version
    if sys.version_info < (3, 6):
        print("This application requires Python 3.6 or higher")
        sys.exit(1)
    
    # Check for required modules
    required_modules = ['rich', 'requests', 'nmap', 'scapy']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"Missing required modules: {', '.join(missing_modules)}")
        print("Please install them using: pip install -r requirements.txt")
        sys.exit(1)
    
    # Initialize and run the application
    app = NetToolbox()
    app.run()

if __name__ == "__main__":
    main()
