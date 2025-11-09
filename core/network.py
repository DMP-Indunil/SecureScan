"""
Network utilities for banner grabbing and service identification
"""

import socket
import ssl


def get_service_banner(ip, port, timeout=2):
    """
    Attempt to grab service banner from the specified port
    
    Args:
        ip (str): Target IP address
        port (int): Port number
        timeout (int): Connection timeout in seconds
        
    Returns:
        str: Service banner or empty string if unavailable
    """
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
