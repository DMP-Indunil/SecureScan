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
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from enum import Enum
from scapy.all import sr, IP, TCP, sr1

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

def scan_port_connect(ip, port, identify=True, output_format="text"):
    """Standard TCP connect scan"""
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
            
            # Store result
            scan_result = {
                "port": port,
                "state": state.value,
                "service": service,
                "banner": banner
            }
            scan_results.append(scan_result)
            
            # Print result based on format
            if output_format == "text":
                if banner:
                    print(f"[+] Port {port} is OPEN: {service} - {banner}")
                else:
                    print(f"[+] Port {port} is OPEN: {service}")
                    
        sock.close()
    except Exception as e:
        if output_format == "text":
            print(f"[-] Error scanning port {port}: {e}")

def scan_port_syn(ip, port, identify=True, output_format="text"):
    """SYN scan (half-open)"""
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
                
                # Store result
                scan_result = {
                    "port": port,
                    "state": state.value,
                    "service": service,
                    "banner": banner
                }
                scan_results.append(scan_result)
                
                # Print result based on format
                if output_format == "text":
                    if banner:
                        print(f"[+] Port {port} is OPEN: {service} - {banner}")
                    else:
                        print(f"[+] Port {port} is OPEN: {service}")
            
            elif tcp_flags == 0x14:  # RST-ACK (port is closed)
                if output_format == "text" and port % 50 == 0:  # Reduce output noise
                    print(f"[-] Port {port} is CLOSED")
            
            else:  # Other flags
                state = PortState.FILTERED
                if output_format == "text" and port % 50 == 0:  # Reduce output noise
                    print(f"[-] Port {port} is FILTERED")
        
        else:  # No response
            state = PortState.FILTERED
            if output_format == "text" and port % 50 == 0:  # Reduce output noise
                print(f"[-] Port {port} is FILTERED (no response)")
                
    except Exception as e:
        if output_format == "text":
            print(f"[-] Error scanning port {port}: {e}")

def scan_port_stealth(ip, port, scan_type=ScanType.FIN, output_format="text"):
    """Stealth scan (FIN, XMAS, NULL)"""
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
            
            # Store result
            scan_result = {
                "port": port,
                "state": state.value,
                "service": service,
                "banner": ""  # No banner for stealth scans
            }
            scan_results.append(scan_result)
            
            if output_format == "text":
                print(f"[+] Port {port} is possibly OPEN: {service} (no response)")
        
        elif response.haslayer(TCP):
            # If we get a RST response, port is closed
            if response.getlayer(TCP).flags & 0x04:  # Check for RST flag
                if output_format == "text" and port % 50 == 0:  # Reduce output noise
                    print(f"[-] Port {port} is CLOSED")
            else:
                # Other responses are unexpected for these scan types
                if output_format == "text" and port % 50 == 0:
                    print(f"[-] Port {port} returned unexpected response")
                    
    except Exception as e:
        if output_format == "text":
            print(f"[-] Error scanning port {port} with {scan_type.value} scan: {e}")

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

def main():
    parser = argparse.ArgumentParser(description="SecureScan - Advanced Port Scanner with Multiple Techniques")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--ports", required=True, help="Port range (e.g., 20-100)")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--no-identify", action="store_true", help="Skip service identification")
    parser.add_argument("--scan-type", choices=["connect", "syn", "fin", "xmas", "null"], default="connect",
                        help="Scan technique (default: connect)")
    parser.add_argument("--output", choices=["text", "json", "csv"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--output-file", help="File to save results (only for json/csv output)")
    args = parser.parse_args()

    ip = args.target
    port_range = args.ports.split("-")
    start_port = int(port_range[0])
    end_port = int(port_range[1])
    thread_count = min(args.threads, (end_port - start_port + 1))  # Ensure we don't create more threads than ports
    
    # Check if we need elevated privileges for SYN, FIN, XMAS or NULL scans
    scan_type = ScanType(args.scan_type)
    if scan_type != ScanType.CONNECT:
        try:
            # Windows doesn't have os.geteuid(), use a more cross-platform approach
            is_admin = False
            if os.name == 'nt':
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                is_admin = os.geteuid() == 0
                
            if not is_admin:
                print(f"\n⚠️  WARNING: {scan_type.value.upper()} scans typically require root/administrator privileges.")
                print("You may not get accurate results without running as administrator/root.")
                input("Press Enter to continue anyway or Ctrl+C to abort...")
        except:
            print(f"\n⚠️  WARNING: Could not determine if you have sufficient privileges for {scan_type.value.upper()} scans.")
            print("You may not get accurate results without running as administrator/root.")
            input("Press Enter to continue anyway or Ctrl+C to abort...")

    identify_services = not args.no_identify
    output_format = args.output
    
    # Clear previous results
    scan_results.clear()
    
    # Print scan information
    print(f"\n🔍 Scanning {ip} from port {start_port} to {end_port}")
    print(f"📊 Scan type: {scan_type.value.upper()}")
    print(f"🧵 Threads: {thread_count}")
    if identify_services and scan_type == ScanType.CONNECT:
        print("🔎 Service identification: Enabled")
    else:
        print("� Service identification: Disabled")
    print(f"📄 Output format: {output_format.upper()}")
    print("")
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        for port in range(start_port, end_port + 1):
            # Only attempt service identification for CONNECT scans
            identify = identify_services if scan_type == ScanType.CONNECT else False
            executor.submit(scan_port, ip, port, identify, scan_type, output_format)
    
    duration = time.time() - start_time
    
    # Print summary
    if output_format == "text":
        print(f"\n✅ Scan completed in {duration:.2f} seconds")
        print(f"🎯 Target: {ip}")
        print(f"🔢 Port range: {start_port}-{end_port}")
        print(f"🧵 Threads used: {thread_count}")
        print(f"📊 Scan type: {scan_type.value.upper()}")
        open_ports = len([r for r in scan_results if r["state"] == "open"])
        print(f"🔓 Open ports: {open_ports}")
    
    # Export results if needed
    if output_format in ["json", "csv"]:
        export_results(output_format, args.output_file)

if __name__ == "__main__":
    main()