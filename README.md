# NetToolbox - Network Security Toolkit

A comprehensive, modern network analysis, exploitation, and monitoring toolbox designed for cybersecurity professionals and enthusiasts.

![NetToolbox Banner](https://img.shields.io/badge/NetToolbox-v1.0-blue) ![Python](https://img.shields.io/badge/Python-3.6%2B-green) ![License](https://img.shields.io/badge/License-MIT-yellow)

## ✨ Features

### 🔍 Network Scanning & Reconnaissance
- **Host Discovery**: ICMP ping sweeps and advanced host enumeration
- **Port Scanning**: TCP/UDP scanning with customizable speed and range
- **Service Detection**: Banner grabbing and version identification
- **OS Fingerprinting**: Operating system detection and analysis
- **Export Results**: Multiple output formats (JSON, CSV, TXT)

### 🌐 Web Application Security
- **HTTP Header Analysis**: Security header inspection
- **Directory Brute Forcing**: Built-in wordlists and custom options
- **Vulnerability Testing**: XSS and SQL injection detection
- **Form Analysis**: Automated form discovery and testing
- **Technology Detection**: CMS and framework identification

### 📡 Packet Analysis & Network Monitoring
- **Real-time Packet Sniffing**: Live network traffic analysis
- **Protocol Analysis**: TCP, UDP, ICMP, ARP, DNS parsing
- **Packet Export**: Save captures to PCAP files
- **Suspicious Activity Detection**: Automated threat identification

### ⚡ Exploitation & Penetration Tools
- **Reverse Shell Listener**: Multi-threaded shell handler
- **Credential Brute Forcing**: SSH, FTP, and other services
- **Payload Generation**: Multiple payload types and encodings
- **Vulnerability Exploitation**: Common exploit techniques

### 📊 Network Monitoring & Alerting
- **Uptime Monitoring**: Continuous host availability checks
- **Service Monitoring**: HTTP, TCP, and custom service checks
- **Alert System**: Real-time notifications and reporting
- **Performance Metrics**: Response time and availability statistics

### 🛠️ Utilities & Information Gathering
- **DNS Operations**: Forward and reverse DNS lookups
- **WHOIS Queries**: Domain registration information
- **GeoIP Lookups**: Geographic location identification
- **Network Calculations**: Subnet and IP range analysis

## 🚀 Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager
- Administrative privileges (for packet sniffing)

### System Dependencies

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install nmap python3-dev python3-pip
# Optional: wireshark-common (for enhanced packet analysis)
sudo apt install wireshark-common
```

#### CentOS/RHEL/Fedora
```bash
sudo yum install nmap python3-devel python3-pip
# or for newer versions:
sudo dnf install nmap python3-devel python3-pip
```

#### macOS
```bash
# Using Homebrew
brew install nmap python3

# Using MacPorts
sudo port install nmap python3
```

#### Windows
1. Install Python 3.6+ from [python.org](https://python.org)
2. Download Nmap from [nmap.org](https://nmap.org/download.html)
3. Install Visual C++ Build Tools (if needed)

### Python Package Installation

```bash
# Clone the repository
git clone https://github.com/mdri11/nettoolbox.git
cd nettoolbox

# Install Python dependencies
pip install -r requirements.txt

# Alternative: Install in virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 🎯 Quick Start

### Basic Usage
```bash
# Run the main application
python main.py

# With specific Python version
python3 main.py
```

### Example Commands
The application provides an interactive menu system, but here are some key operations:

1. **Network Scanning**: Choose option 1 from main menu
2. **Web Security Testing**: Choose option 2 from main menu  
3. **Packet Analysis**: Choose option 3 from main menu
4. **Monitoring Setup**: Choose option 5 from main menu

## 📁 Project Structure

```
NetToolbox/
├── main.py                 # Main application entry point
├── modules/                # Core functionality modules
│   ├── __init__.py
│   ├── network_scanner.py  # Network scanning tools
│   ├── web_scanner.py      # Web security testing
│   ├── packet_analyzer.py  # Packet capture and analysis
│   ├── exploitation_tools.py # Penetration testing utilities
│   ├── monitoring_tools.py # Network monitoring
│   ├── utilities.py        # General network utilities  
│   └── logger.py          # Logging and reporting
├── logs/                   # Application logs (auto-created)
├── results/               # Scan results (auto-created)
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## 🔧 Configuration

### Logging Configuration
Logs are automatically saved to the `logs/` directory with timestamps. Log levels can be configured in the settings menu.

### Results Export
All scan results are automatically saved in JSON format to the `results/` directory. Additional export formats (CSV, TXT) are available through the export menu.

### Custom Wordlists
Place custom wordlists in the project directory and specify them during directory brute forcing operations.

## 🛡️ Security Considerations

### Legal and Ethical Usage
- **Authorization Required**: Only use against networks and systems you own or have explicit permission to test
- **Responsible Disclosure**: Report vulnerabilities through proper channels
- **Compliance**: Ensure compliance with local laws and regulations
- **Rate Limiting**: Use appropriate delays to avoid overwhelming target systems

### Best Practices
- Run scans during maintenance windows when possible
- Document all testing activities
- Use minimal necessary scan intensities
- Respect robot.txt and terms of service
- Keep scanning tools updated

## 🔍 Troubleshooting

### Common Issues

#### "Permission denied" for packet sniffing
```bash
# Linux: Run with sudo or add user to wireshark group
sudo python main.py
# or
sudo usermod -a -G wireshark $USER
```

#### "nmap not found" error
- Ensure nmap is installed and in system PATH
- Try reinstalling nmap package
- Verify installation with `nmap --version`

#### Import errors for scapy
```bash
# Install with specific options
pip install --no-binary :all: scapy
# or
pip install scapy[complete]
```

#### Windows-specific issues
- Install Microsoft Visual C++ Build Tools
- Use Command Prompt as Administrator
- Disable Windows Firewall temporarily for testing

### Performance Optimization
- Adjust thread counts for your system capabilities
- Use targeted scans instead of broad sweeps
- Enable result caching for repeated operations
- Monitor system resources during intensive scans

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest pytest-cov black flake8

# Run tests
pytest tests/

# Format code
black .

# Lint code
flake8 .
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **Issues**: Report bugs and request features via GitHub Issues
- **Documentation**: Additional documentation available in `docs/` directory
- **Community**: Join our Discord server for discussions and support

## ⚠️ Disclaimer

This tool is for educational and authorized testing purposes only. The developers are not responsible for any misuse or damage caused by this software. Users are solely responsible for ensuring they have proper authorization before using these tools on any network or system.

## 🎖️ Acknowledgments

- **Nmap Project**: For the excellent network mapping tool
- **Scapy Community**: For powerful packet manipulation capabilities
- **Rich Library**: For beautiful console interfaces
- **Security Community**: For continuous feedback and improvements

---

**Made with ❤️ by the NetToolbox Team**

*Stay secure, scan responsibly! 🔐*
