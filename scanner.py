import socket
import argparse
import threading
import time
import ssl
import json
import csv
import sys
import os
import struct
import re
import ipaddress
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from enum import Enum

# Try importing scapy, handle if not installed
try:
    from scapy.all import sr, IP, TCP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  WARNING: Scapy is not installed. Advanced scan types (SYN, FIN, XMAS, NULL) will not be available.")
    print("Install it with: pip install scapy")
    print("Only CONNECT scan will be available.\n")

# Try importing tqdm for progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    # Progress bar is optional, so just use a simple counter

# Scan types
class ScanType(Enum):
    CONNECT = "connect"  # Basic TCP connect scan
    SYN = "syn"          # SYN scan (half-open)
    FIN = "fin"          # FIN scan
    XMAS = "xmas"        # XMAS scan (FIN, PSH, URG)
    NULL = "null"        # NULL scan

# Port states
class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"

# Common port to service mappings
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    135: "Microsoft RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL/MariaDB",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP Alt",
    8443: "HTTPS Alt"
}

# Global results list to store scan findings
scan_results = []
scan_results_lock = threading.Lock()

# Global progress tracking
progress_bar = None
scanned_ports = 0
open_ports_count = 0
closed_ports_count = 0
filtered_ports_count = 0
progress_lock = threading.Lock()

# Validation Functions
def is_valid_ip(ip):
    """Validate IP address format"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port):
    """Validate port number"""
    return 1 <= port <= 65535

def is_admin():
    """Check if the script is running with administrator/root privileges"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Unix/Mac
            return os.geteuid() == 0
    except Exception:
        return False

def validate_arguments(args):
    """Validate all command-line arguments"""
    errors = []
    
    # Validate IP address
    if not is_valid_ip(args.target):
        errors.append(f"❌ Invalid IP address: {args.target}")
    
    # Validate port range
    try:
        port_range = args.ports.split("-")
        if len(port_range) != 2:
            errors.append(f"❌ Invalid port range format: {args.ports}. Use format: START-END (e.g., 1-1000)")
        else:
            start_port = int(port_range[0])
            end_port = int(port_range[1])
            
            if not is_valid_port(start_port):
                errors.append(f"❌ Invalid start port: {start_port}. Must be between 1-65535")
            if not is_valid_port(end_port):
                errors.append(f"❌ Invalid end port: {end_port}. Must be between 1-65535")
            if start_port > end_port:
                errors.append(f"❌ Start port ({start_port}) cannot be greater than end port ({end_port})")
    except ValueError:
        errors.append(f"❌ Port range must contain numbers: {args.ports}")
    
    # Validate threads
    if args.threads < 1:
        errors.append(f"❌ Thread count must be at least 1, got: {args.threads}")
    elif args.threads > 1000:
        errors.append(f"⚠️  WARNING: Thread count of {args.threads} is very high and may cause issues")
    
    # Validate scan type with scapy availability
    if args.scan_type != "connect" and not SCAPY_AVAILABLE:
        errors.append(f"❌ Scan type '{args.scan_type}' requires Scapy. Install with: pip install scapy")
    
    # Check admin privileges for advanced scans
    if args.scan_type != "connect" and not is_admin():
        errors.append(f"⚠️  WARNING: '{args.scan_type}' scan requires administrator/root privileges")
    
    # Validate output file if specified
    if args.output_file:
        if args.output == "text":
            errors.append(f"⚠️  WARNING: --output-file is ignored when output format is 'text'")
        
        # Check if directory exists
        output_dir = os.path.dirname(args.output_file)
        if output_dir and not os.path.exists(output_dir):
            errors.append(f"❌ Output directory does not exist: {output_dir}")
    
    return errors

def get_service_banner(ip, port, timeout=2):
    """Attempt to grab service banner from the specified port"""
    banner = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # For common HTTP(S) ports, try to get server header
        if port in [80, 443, 8080, 8443]:
            try:
                if port in [443, 8443]:  # HTTPS ports
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    s = context.wrap_socket(sock, server_hostname=ip)
                else:
                    s = sock
                
                s.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nUser-Agent: SecureScan\r\n\r\n")
                response = s.recv(1024).decode('utf-8', errors='ignore')
                server_line = [line for line in response.split('\r\n') if line.startswith('Server:')]
                if server_line:
                    banner = server_line[0][8:].strip()
            except:
                pass
        else:  # For other ports, try to grab initial banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
        sock.close()
    except:
        # Failed to get banner, which is normal for many services
        pass
        
    return banner.strip()

def update_progress():
    """Update the progress bar"""
    global scanned_ports, progress_bar
    with progress_lock:
        scanned_ports += 1
        if progress_bar and TQDM_AVAILABLE:
            progress_bar.update(1)

def scan_port_connect(ip, port, identify=True, output_format="text"):
    """Standard TCP connect scan"""
    global open_ports_count
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            state = PortState.OPEN
            banner = ""
            
            # If identification is enabled, try to get the banner
            if identify:
                banner = get_service_banner(ip, port)
            
            # Store result (thread-safe)
            scan_result = {
                "port": port,
                "state": state.value,
                "service": service,
                "banner": banner
            }
            with scan_results_lock:
                scan_results.append(scan_result)
                open_ports_count += 1
            
            # Print result based on format (only if not using progress bar)
            if output_format == "text" and not TQDM_AVAILABLE:
                if banner:
                    print(f"[+] Port {port} is OPEN: {service} - {banner}")
                else:
                    print(f"[+] Port {port} is OPEN: {service}")
                    
        sock.close()
    except socket.gaierror:
        if output_format == "text" and not TQDM_AVAILABLE:
            print(f"[-] Could not resolve hostname for {ip}")
    except socket.error as e:
        if output_format == "text" and not TQDM_AVAILABLE:
            print(f"[-] Socket error on port {port}: {e}")
    except Exception as e:
        if output_format == "text" and not TQDM_AVAILABLE:
            print(f"[-] Unexpected error scanning port {port}: {e}")
    finally:
        update_progress()

def scan_port_syn(ip, port, identify=True, output_format="text"):
    """SYN scan (half-open)"""
    global open_ports_count
    try:
        # SYN scan using scapy
        packet = IP(dst=ip)/TCP(dport=port, flags="S")  # SYN flag
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            # Check TCP flags in response
            tcp_flags = response.getlayer(TCP).flags
            
            if tcp_flags == 0x12:  # SYN-ACK (port is open)
                # Send RST to close connection
                rst = IP(dst=ip)/TCP(dport=port, flags="R")
                sr(rst, timeout=1, verbose=0)
                
                service = COMMON_PORTS.get(port, "Unknown")
                state = PortState.OPEN
                banner = ""
                
                # For SYN scan, we need to do a separate connect for banner grabbing
                if identify:
                    banner = get_service_banner(ip, port)
                
                # Store result (thread-safe)
                scan_result = {
                    "port": port,
                    "state": state.value,
                    "service": service,
                    "banner": banner
                }
                with scan_results_lock:
                    scan_results.append(scan_result)
                    open_ports_count += 1
                
                # Print result based on format
                if output_format == "text" and not TQDM_AVAILABLE:
                    if banner:
                        print(f"[+] Port {port} is OPEN: {service} - {banner}")
                    else:
                        print(f"[+] Port {port} is OPEN: {service}")
            
            elif tcp_flags == 0x14:  # RST-ACK (port is closed)
                if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:  # Reduce output noise
                    print(f"[-] Port {port} is CLOSED")
            
            else:  # Other flags
                state = PortState.FILTERED
                if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:  # Reduce output noise
                    print(f"[-] Port {port} is FILTERED")
        
        else:  # No response
            state = PortState.FILTERED
            if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:  # Reduce output noise
                print(f"[-] Port {port} is FILTERED (no response)")
                
    except Exception as e:
        if output_format == "text" and not TQDM_AVAILABLE:
            print(f"[-] Error scanning port {port}: {e}")
    finally:
        update_progress()

def scan_port_stealth(ip, port, scan_type=ScanType.FIN, output_format="text"):
    """Stealth scan (FIN, XMAS, NULL)"""
    global open_ports_count
    try:
        # Set appropriate TCP flags based on scan type
        if scan_type == ScanType.FIN:
            flags = "F"  # FIN scan
        elif scan_type == ScanType.XMAS:
            flags = "FPU"  # XMAS scan (FIN, PSH, URG)
        elif scan_type == ScanType.NULL:
            flags = ""  # NULL scan (no flags)
        else:
            return
        
        # Send packet with appropriate flags
        packet = IP(dst=ip)/TCP(dport=port, flags=flags)
        response = sr1(packet, timeout=1, verbose=0)
        
        if response is None:
            # No response typically means open|filtered for these scan types
            state = PortState.OPEN_FILTERED
            service = COMMON_PORTS.get(port, "Unknown")
            
            # Store result (thread-safe)
            scan_result = {
                "port": port,
                "state": state.value,
                "service": service,
                "banner": ""  # No banner for stealth scans
            }
            with scan_results_lock:
                scan_results.append(scan_result)
                open_ports_count += 1
            
            if output_format == "text" and not TQDM_AVAILABLE:
                print(f"[+] Port {port} is possibly OPEN: {service} (no response)")
        
        elif response.haslayer(TCP):
            # If we get a RST response, port is closed
            if response.getlayer(TCP).flags & 0x04:  # Check for RST flag
                if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:  # Reduce output noise
                    print(f"[-] Port {port} is CLOSED")
            else:
                # Other responses are unexpected for these scan types
                if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:
                    print(f"[-] Port {port} returned unexpected response")
                    
    except Exception as e:
        if output_format == "text" and not TQDM_AVAILABLE:
            print(f"[-] Error scanning port {port} with {scan_type.value} scan: {e}")
    finally:
        update_progress()

def scan_port(ip, port, identify=True, scan_type=ScanType.CONNECT, output_format="text"):
    """Main scan function that delegates to specific scan type"""
    if scan_type == ScanType.CONNECT:
        scan_port_connect(ip, port, identify, output_format)
    elif scan_type == ScanType.SYN:
        scan_port_syn(ip, port, identify, output_format)
    elif scan_type in [ScanType.FIN, ScanType.XMAS, ScanType.NULL]:
        scan_port_stealth(ip, port, scan_type, output_format)

def export_results(output_format, output_file=None):
    """Export scan results to the specified format"""
    if not scan_results:
        print("No results to export")
        return
    
    if output_format == "json":
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(scan_results, f, indent=4)
            print(f"\nResults exported to {output_file} in JSON format")
        else:
            print("\nJSON Results:")
            print(json.dumps(scan_results, indent=4))
            
    elif output_format == "csv":
        if output_file:
            with open(output_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
                writer.writeheader()
                writer.writerows(scan_results)
            print(f"\nResults exported to {output_file} in CSV format")
        else:
            output = []
            output.append("port,state,service,banner")
            for result in scan_results:
                # Escape any commas in the banner
                banner = f'"{result["banner"]}"' if ',' in result["banner"] else result["banner"]
                output.append(f"{result['port']},{result['state']},{result['service']},{banner}")
            print("\nCSV Results:")
            print("\n".join(output))

def generate_statistics(total_ports, duration, start_port, end_port):
    """Generate comprehensive scan statistics"""
    from collections import Counter
    
    # Calculate port state counts
    open_count = len([r for r in scan_results if r["state"] == "open"])
    open_filtered_count = len([r for r in scan_results if r["state"] == "open|filtered"])
    closed_count = total_ports - open_count - open_filtered_count
    
    # Calculate scan efficiency
    ports_per_second = total_ports / duration if duration > 0 else 0
    
    # Get service distribution
    services = [r["service"] for r in scan_results if r["state"] == "open"]
    service_counter = Counter(services)
    
    # Security risk assessment (based on commonly exploited ports)
    high_risk_ports = {21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5900, 8080}
    risky_ports = [r for r in scan_results if r["port"] in high_risk_ports and r["state"] == "open"]
    
    return {
        "total_ports_scanned": total_ports,
        "open_ports": open_count,
        "open_filtered_ports": open_filtered_count,
        "closed_ports": closed_count,
        "scan_duration": duration,
        "ports_per_second": ports_per_second,
        "service_distribution": service_counter,
        "high_risk_ports": risky_ports,
        "port_range": f"{start_port}-{end_port}"
    }

def print_statistics(stats):
    """Print formatted statistics"""
    print("\n" + "="*60)
    print("📊 SCAN STATISTICS".center(60))
    print("="*60)
    
    # Port status breakdown
    print(f"\n📈 Port Status Breakdown:")
    print(f"   Total Ports Scanned:  {stats['total_ports_scanned']:,}")
    print(f"   🟢 Open:              {stats['open_ports']:,} ({stats['open_ports']/stats['total_ports_scanned']*100:.1f}%)")
    
    if stats['open_filtered_ports'] > 0:
        print(f"   🟡 Open|Filtered:     {stats['open_filtered_ports']:,} ({stats['open_filtered_ports']/stats['total_ports_scanned']*100:.1f}%)")
    
    print(f"   🔴 Closed/Filtered:   {stats['closed_ports']:,} ({stats['closed_ports']/stats['total_ports_scanned']*100:.1f}%)")
    
    # Performance metrics
    print(f"\n⚡ Performance Metrics:")
    print(f"   Scan Duration:        {stats['scan_duration']:.2f} seconds")
    print(f"   Scan Speed:           {stats['ports_per_second']:.2f} ports/second")
    print(f"   Average Time/Port:    {(stats['scan_duration']/stats['total_ports_scanned']*1000):.2f} ms")
    
    # Service distribution
    if stats['service_distribution']:
        print(f"\n🔎 Top Services Discovered:")
        for service, count in stats['service_distribution'].most_common(5):
            print(f"   • {service:20s} {count:3d} port(s)")
    
    # Security assessment
    if stats['high_risk_ports']:
        print(f"\n⚠️  Security Assessment:")
        print(f"   High-Risk Ports Open: {len(stats['high_risk_ports'])}")
        for port_info in stats['high_risk_ports'][:5]:  # Show first 5
            print(f"   • Port {port_info['port']:5d} - {port_info['service']}")
        if len(stats['high_risk_ports']) > 5:
            print(f"   ... and {len(stats['high_risk_ports']) - 5} more")
    else:
        print(f"\n✅ Security Assessment:")
        print(f"   No commonly exploited ports detected as open.")
    
    print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(
        description="SecureScan - Advanced Port Scanner with Multiple Techniques",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python scanner.py --target 192.168.1.1 --ports 1-1000
  
  Fast multi-threaded scan:
    python scanner.py --target 192.168.1.1 --ports 1-1000 --threads 100
  
  SYN scan with JSON output:
    python scanner.py --target 192.168.1.1 --ports 1-1000 --scan-type syn --output json --output-file results.json
  
  Stealth FIN scan:
    python scanner.py --target 192.168.1.1 --ports 1-1000 --scan-type fin

Note: Advanced scan types (SYN, FIN, XMAS, NULL) require administrator/root privileges.
        """
    )
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--ports", required=True, help="Port range (e.g., 1-1000)")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--no-identify", action="store_true", help="Skip service identification")
    parser.add_argument("--scan-type", choices=["connect", "syn", "fin", "xmas", "null"], default="connect",
                        help="Scan technique (default: connect)")
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output-file", help="File to save results (only for json/csv output)")
    
    try:
        args = parser.parse_args()
    except SystemExit:
        return
    
    # Validate arguments
    validation_errors = validate_arguments(args)
    
    # Separate critical errors from warnings
    critical_errors = [e for e in validation_errors if e.startswith("❌")]
    warnings = [e for e in validation_errors if e.startswith("⚠️")]
    
    # Display warnings
    if warnings:
        for warning in warnings:
            print(warning)
        print()
    
    # Exit on critical errors
    if critical_errors:
        print("\n🛑 Critical errors found:\n")
        for error in critical_errors:
            print(error)
        print("\nPlease fix the errors above and try again.")
        sys.exit(1)
    
    # Ask for confirmation if there are warnings about privileges
    if any("administrator/root privileges" in w for w in warnings):
        try:
            response = input("Continue anyway? (y/n): ").strip().lower()
            if response != 'y':
                print("Scan cancelled.")
                sys.exit(0)
        except KeyboardInterrupt:
            print("\n\nScan cancelled by user.")
            sys.exit(0)
    
    try:
        ip = args.target
        port_range = args.ports.split("-")
        start_port = int(port_range[0])
        end_port = int(port_range[1])
        thread_count = min(args.threads, (end_port - start_port + 1))  # Ensure we don't create more threads than ports
        scan_type = ScanType(args.scan_type)
    except Exception as e:
        print(f"❌ Error parsing arguments: {e}")
        sys.exit(1)

    identify_services = not args.no_identify
    output_format = args.output
    
    # Clear previous results
    global scan_results, scanned_ports, open_ports_count, progress_bar
    scan_results.clear()
    scanned_ports = 0
    open_ports_count = 0
    
    # Print scan information
    print(f"\n🔍 Scanning {ip} from port {start_port} to {end_port}")
    print(f"📊 Scan type: {scan_type.value.upper()}")
    print(f"🧵 Threads: {thread_count}")
    if identify_services and scan_type == ScanType.CONNECT:
        print("🔎 Service identification: Enabled")
    else:
        print("🔎 Service identification: Disabled")
    print(f"📄 Output format: {output_format.upper()}")
    print("")
    
    start_time = time.time()
    total_ports = end_port - start_port + 1
    
    try:
        # Initialize progress bar if tqdm is available and output format is text
        if TQDM_AVAILABLE and output_format == "text":
            progress_bar = tqdm(
                total=total_ports,
                desc="🔍 Scanning ports",
                unit="port",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} ports [{elapsed}<{remaining}, {rate_fmt}]",
                ncols=100
            )
        
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            for port in range(start_port, end_port + 1):
                # Only attempt service identification for CONNECT scans
                identify = identify_services if scan_type == ScanType.CONNECT else False
                executor.submit(scan_port, ip, port, identify, scan_type, output_format)
        
        # Close progress bar
        if progress_bar and TQDM_AVAILABLE:
            progress_bar.close()
            progress_bar = None
            
            # Print open ports summary after progress bar
            if scan_results:
                print(f"\n📋 Open ports found:")
                for result in sorted(scan_results, key=lambda x: x['port']):
                    if result['banner']:
                        print(f"  [+] Port {result['port']}: {result['service']} - {result['banner']}")
                    else:
                        print(f"  [+] Port {result['port']}: {result['service']}")
            
    except KeyboardInterrupt:
        if progress_bar and TQDM_AVAILABLE:
            progress_bar.close()
            progress_bar = None
        print("\n\n⚠️  Scan interrupted by user (Ctrl+C)")
        print(f"📊 Partial results collected: {len(scan_results)} open ports found")
    except Exception as e:
        if progress_bar and TQDM_AVAILABLE:
            progress_bar.close()
            progress_bar = None
        print(f"\n\n❌ Error during scan: {e}")
        print(f"📊 Partial results collected: {len(scan_results)} open ports found")
    
    duration = time.time() - start_time
    
    # Generate and print statistics for text output
    if output_format == "text":
        stats = generate_statistics(total_ports, duration, start_port, end_port)
        print_statistics(stats)
        
        # Print basic summary
        print(f"\n📋 Scan Summary:")
        print(f"   🎯 Target:        {ip}")
        print(f"   🔢 Port Range:    {start_port}-{end_port}")
        print(f"   🧵 Threads Used:  {thread_count}")
        print(f"   📊 Scan Type:     {scan_type.value.upper()}")
        print(f"   ✅ Status:        Completed")
    
    # Export results if needed
    try:
        if output_format in ["json", "csv"]:
            export_results(output_format, args.output_file)
            
            # Also print statistics for non-text formats
            if output_format == "json" and not args.output_file:
                stats = generate_statistics(total_ports, duration, start_port, end_port)
                print(f"\nScan completed: {stats['open_ports']} open ports found in {duration:.2f}s")
            elif output_format == "csv" and not args.output_file:
                stats = generate_statistics(total_ports, duration, start_port, end_port)
                print(f"\nScan completed: {stats['open_ports']} open ports found in {duration:.2f}s")
    except Exception as e:
        print(f"\n❌ Error exporting results: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Program terminated by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)