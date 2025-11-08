# SecureScan
A lightweight network vulnerability scanner built with Python

## Features
- 🚀 Multi-threaded scanning for high performance
- 🔍 Multiple scan types (Connect, SYN, FIN, XMAS, NULL)
- 🎯 Service identification and banner grabbing
- 📊 Multiple output formats (Text, JSON, CSV)
- ⚡ Configurable thread count for optimal speed
- 🛡️ Stealth scanning capabilities

## Installation

### Prerequisites
- Python 3.7 or higher
- Administrator/Root privileges (required for SYN and stealth scans)

### Steps

1. Clone the repository:
```bash
git clone https://github.com/DMP-Indunil/SecureScan.git
cd SecureScan
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

**Note for Windows users:**
- You may need to install Npcap for Scapy to work: https://npcap.com/
- Run PowerShell/Command Prompt as Administrator for advanced scan types

**Note for Linux users:**
```bash
sudo pip install -r requirements.txt
```

## Usage

### Basic Syntax
```bash
python scanner.py --target <IP_ADDRESS> --ports <PORT_RANGE> [OPTIONS]
```

### Examples

**Simple Port Scan:**
```bash
python scanner.py --target 192.168.1.1 --ports 1-1000
```

**Fast Multi-threaded Scan:**
```bash
python scanner.py --target 192.168.1.1 --ports 1-1000 --threads 100
```

**Stealth SYN Scan (requires admin):**
```bash
python scanner.py --target 192.168.1.1 --ports 1-1000 --scan-type syn
```

**Export Results to JSON:**
```bash
python scanner.py --target 192.168.1.1 --ports 1-1000 --output json --output-file results.json
```

**Export Results to CSV:**
```bash
python scanner.py --target 192.168.1.1 --ports 1-1000 --output csv --output-file results.csv
```

**Advanced Stealth Scans:**
```bash
# FIN Scan
python scanner.py --target 192.168.1.1 --ports 1-1000 --scan-type fin

# XMAS Scan
python scanner.py --target 192.168.1.1 --ports 1-1000 --scan-type xmas

# NULL Scan
python scanner.py --target 192.168.1.1 --ports 1-1000 --scan-type null
```

## Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Target IP address (required) | - |
| `--ports` | Port range (e.g., "1-1000") (required) | - |
| `--threads` | Number of concurrent threads | 50 |
| `--scan-type` | Scan type: connect, syn, fin, xmas, null | connect |
| `--output` | Output format: text, json, csv | text |
| `--output-file` | File to save results | - |
| `--no-identify` | Skip service identification (faster) | False |

## Scan Types

- **Connect Scan**: Standard TCP connection (default, no special privileges needed)
- **SYN Scan**: Half-open scan, stealthier than connect scan (requires admin)
- **FIN Scan**: Sends FIN packets, can bypass some firewalls (requires admin)
- **XMAS Scan**: Sends FIN, PSH, URG flags (requires admin)
- **NULL Scan**: Sends packets with no flags (requires admin)

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is for educational and authorized security testing purposes only.

- Only scan systems you own or have explicit permission to test
- Unauthorized port scanning may be illegal in your jurisdiction
- Users are responsible for complying with all applicable laws
- The authors assume no liability for misuse of this tool

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Author

**DMP-Indunil**
- GitHub: [@DMP-Indunil](https://github.com/DMP-Indunil)

## Roadmap

- [ ] Progress bar with real-time statistics
- [ ] OS detection
- [ ] Vulnerability database integration
- [ ] Subnet scanning
- [ ] GUI interface
- [ ] UDP scanning support
