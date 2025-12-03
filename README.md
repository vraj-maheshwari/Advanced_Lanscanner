# 🚀 LAN Scanner Pro - Enhanced Network Discovery & Security Tool

A powerful, feature-rich LAN scanner built with Python and Tkinter, designed for network administrators, security professionals, and IT enthusiasts.

## ✨ Features

### 🔍 Core Scanning Capabilities
- **Multi-threaded Network Scanning** - Fast and efficient scanning with configurable worker threads
- **CIDR Network Support** - Scan entire subnets (e.g., 192.168.1.0/24)
- **Flexible Port Scanning** - Common ports, custom ranges, or specific ports
- **Reverse DNS Lookup** - Optional hostname resolution
- **Banner Grabbing** - Service identification and version detection
- **Vulnerability Assessment** - Security hints for common services

### 🎨 Modern User Interface
- **Material Design** - Clean, professional interface with intuitive controls
- **Tabbed Interface** - Organized results, topology, statistics, and logs
- **Real-time Updates** - Live progress tracking and statistics
- **Search & Filtering** - Find specific hosts or filter by criteria
- **Responsive Layout** - Adapts to different screen sizes

### 📊 Advanced Features
- **Network Topology Visualization** - Visual representation of discovered hosts
- **Statistical Analysis** - Charts and graphs of scan results
- **Comprehensive Logging** - Detailed activity logs with timestamps
- **Configuration Profiles** - Save and load scan configurations
- **Multiple Export Formats** - CSV, JSON, HTML, and Text reports

### 🛠️ Utility Tools
- **Network Discovery** - Automatically detect local network
- **Ping Testing** - Connectivity testing for discovered hosts
- **Detailed Port Scanner** - In-depth port analysis for specific hosts
- **Device Fingerprinting** - OS and device type identification
- **Port Presets** - Quick access to common scanning scenarios

### 🔒 Security Features
- **Vulnerability Hints** - Security recommendations for open services
- **Service Detection** - Identify running services and versions
- **Security Assessment** - Risk evaluation of discovered hosts
- **Export Security** - Secure reporting with configurable detail levels

## 🚀 Getting Started

### Prerequisites
- Python 3.7 or higher
- Windows, macOS, or Linux
- Network access (for scanning)

### Installation

1. **Clone or download** the project files
2. **Install dependencies** (optional for enhanced features):
   ```bash
   pip install matplotlib
   pip install ping3
   pip install python-nmap
   ```
3. **Run the scanner**:
   ```bash
   python lanscannerr.py
   ```

### Basic Usage

1. **Launch the application**
2. **Configure scan parameters**:
   - Network range (CIDR format)
   - Ports to scan
   - Timeout and worker settings
3. **Click "Start Scan"** to begin
4. **Monitor progress** in real-time
5. **Review results** in the organized tabs
6. **Export findings** in your preferred format

## 📋 Scan Configuration

### Network Ranges
- **Single IP**: `192.168.1.1`
- **Subnet**: `192.168.1.0/24` (256 hosts)
- **Custom Range**: `192.168.1.10-192.168.1.50`

### Port Options
- **Common**: Predefined important ports
- **Web Services**: `80,443,8080,8443`
- **Full Range**: `1-1024` (first 1024 ports)
- **Custom**: `22,80,443,8080-8090`

### Advanced Settings
- **Timeout**: Connection timeout in seconds
- **Workers**: Number of concurrent scanning threads
- **Reverse DNS**: Hostname resolution
- **Banner Grabbing**: Service version detection
- **Vulnerability Checks**: Security assessment

## 📊 Understanding Results

### Host Status
- 🟢 **Active**: Hosts with open ports
- ⚪ **Inactive**: Hosts with no open ports

### Service Information
- **Port/Service**: `80/http`, `443/https`
- **Banners**: Service version details
- **Vulnerabilities**: Security recommendations

### Statistics
- **Total Hosts**: All scanned addresses
- **Active Hosts**: Hosts with open services
- **Open Ports**: Total open ports found
- **Vulnerabilities**: Security issues detected

## 🛠️ Advanced Features

### Network Topology
Visual representation of discovered hosts showing:
- Network layout
- Host relationships
- Connection patterns

### Device Fingerprinting
Automatic identification of:
- Operating system hints
- Device types
- Service patterns
- Security assessments

### Export Options
Multiple report formats:
- **CSV**: Excel-compatible data
- **JSON**: Structured data export
- **HTML**: Professional web reports
- **Text**: Simple text summaries

## 🔧 Configuration Profiles

Save and load scan configurations:
1. **Configure** your preferred settings
2. **Save Profile** with a descriptive name
3. **Load Profile** to restore settings
4. **Share** configurations with team members

## 📝 Logging and Monitoring

### Activity Logs
- **Timestamped entries** for all activities
- **Scan progress** tracking
- **Error reporting** and debugging
- **User action** logging

### Real-time Statistics
- **Live updates** during scanning
- **Performance metrics** tracking
- **Resource usage** monitoring

## 🚨 Security Considerations

### Responsible Usage
- **Authorized Networks Only**: Only scan networks you own or have permission to test
- **Rate Limiting**: Use appropriate timeout and worker settings
- **Legal Compliance**: Ensure compliance with local laws and regulations

### Best Practices
- **Test on Lab Networks** before production use
- **Document Findings** for security assessments
- **Regular Scanning** for network monitoring
- **Vulnerability Tracking** for security improvements

## 🐛 Troubleshooting

### Common Issues
- **Permission Denied**: Run as administrator/root if needed
- **Slow Scanning**: Reduce worker threads or increase timeout
- **No Results**: Check network configuration and firewall settings
- **Import Errors**: Install required dependencies

### Performance Tips
- **Optimize Workers**: Balance between speed and system resources
- **Network Conditions**: Consider network congestion and latency
- **Target Selection**: Focus on specific subnets for efficiency

## 🤝 Contributing

### Feature Requests
- **Enhancement Ideas**: Suggest new features
- **Bug Reports**: Report issues and problems
- **Documentation**: Help improve guides and examples

### Development
- **Code Improvements**: Submit pull requests
- **Testing**: Help test on different platforms
- **Localization**: Add language support

## 📄 License

This project is provided as-is for educational and authorized network administration purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

## 🙏 Acknowledgments

- **Python Community** for excellent libraries and tools
- **Network Security Community** for best practices and guidance
- **Open Source Contributors** for inspiration and code examples

---

**⚠️ Disclaimer**: This tool is designed for legitimate network administration and security testing. Users must ensure they have proper authorization before scanning any network. The developers are not responsible for misuse of this software.

**🚀 Happy Scanning!** Discover your network, identify security issues, and maintain a secure infrastructure.
