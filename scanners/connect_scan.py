"""
TCP Connect scan implementation
"""

import socket
from core.ports import PortState, COMMON_PORTS
from core.network import get_service_banner

# Try importing tqdm for progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class ConnectScanner:
    """TCP Connect scan implementation"""
    
    @staticmethod
    def scan_port(ip, port, identify=True, output_format="text", scan_results=None, 
                  scan_results_lock=None, open_ports_count=None, update_progress_callback=None):
        """
        Perform TCP connect scan on a single port
        
        Args:
            ip (str): Target IP address
            port (int): Port to scan
            identify (bool): Whether to perform service identification
            output_format (str): Output format (text/json/csv)
            scan_results (list): Shared results list
            scan_results_lock (Lock): Thread lock for results
            open_ports_count (dict): Counter for open ports
            update_progress_callback (callable): Progress update function
        """
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
                
                if scan_results is not None and scan_results_lock is not None:
                    with scan_results_lock:
                        scan_results.append(scan_result)
                        if open_ports_count is not None:
                            open_ports_count['count'] += 1
                
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
            if update_progress_callback:
                update_progress_callback()
