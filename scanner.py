import socket
import argparse

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # 1 second timeout
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
        sock.close()
    except Exception as e:
        print(f"[-] Error scanning port {port}: {e}")

def main():
    parser = argparse.ArgumentParser(description="SecureScan - Basic TCP Port Scanner")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--ports", required=True, help="Port range (e.g., 20-100)")
    args = parser.parse_args()

    ip = args.target
    port_range = args.ports.split("-")
    start_port = int(port_range[0])
    end_port = int(port_range[1])

    print(f"\n🔍 Scanning {ip} from port {start_port} to {end_port}...\n")

    for port in range(start_port, end_port + 1):
        scan_port(ip, port)

if __name__ == "__main__":
    main()