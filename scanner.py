import socket
import argparse
import threading
import time
import ssl
from queue import Queue
from concurrent.futures import ThreadPoolExecutor

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

def scan_port(ip, port, identify=True):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        result = sock.connect_ex((ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            
            # If identification is enabled, try to get the banner
            banner = ""
            if identify:
                banner = get_service_banner(ip, port)
                if banner:
                    print(f"[+] Port {port} is OPEN: {service} - {banner}")
                else:
                    print(f"[+] Port {port} is OPEN: {service}")
            else:
                print(f"[+] Port {port} is OPEN: {service}")
                
        sock.close()
    except Exception as e:
        print(f"[-] Error scanning port {port}: {e}")

def main():
    parser = argparse.ArgumentParser(description="SecureScan - Multi-threaded TCP Port Scanner with Service Identification")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--ports", required=True, help="Port range (e.g., 20-100)")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--no-identify", action="store_true", help="Skip service identification")
    args = parser.parse_args()

    ip = args.target
    port_range = args.ports.split("-")
    start_port = int(port_range[0])
    end_port = int(port_range[1])
    thread_count = min(args.threads, (end_port - start_port + 1))  # Ensure we don't create more threads than ports

    identify_services = not args.no_identify
    
    if identify_services:
        print(f"\n🔍 Scanning {ip} from port {start_port} to {end_port} using {thread_count} threads with service identification...\n")
    else:
        print(f"\n🔍 Scanning {ip} from port {start_port} to {end_port} using {thread_count} threads...\n")
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port, identify_services)
    
    duration = time.time() - start_time
    print(f"\n✅ Scan completed in {duration:.2f} seconds")
    print(f"🎯 Target: {ip}")
    print(f"🔢 Port range: {start_port}-{end_port}")
    print(f"🧵 Threads used: {thread_count}")

if __name__ == "__main__":
    main()