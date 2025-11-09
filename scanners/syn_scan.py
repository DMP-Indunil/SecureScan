"""
SYN scan implementation (requires scapy and admin privileges)
"""

from core.ports import PortState, COMMON_PORTS
from core.network import get_service_banner

# Try importing scapy
try:
    from scapy.all import sr, IP, TCP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Try importing tqdm for progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class SynScanner:
    """SYN scan (half-open) implementation"""
    
    @staticmethod
    def scan_port(ip, port, identify=True, output_format="text", scan_results=None,
                  scan_results_lock=None, open_ports_count=None, update_progress_callback=None):
        """
        Perform SYN scan on a single port
        
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
        if not SCAPY_AVAILABLE:
            if output_format == "text" and not TQDM_AVAILABLE:
                print(f"[-] Scapy not available, cannot perform SYN scan on port {port}")
            if update_progress_callback:
                update_progress_callback()
            return
            
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
                    
                    if scan_results is not None and scan_results_lock is not None:
                        with scan_results_lock:
                            scan_results.append(scan_result)
                            if open_ports_count is not None:
                                open_ports_count['count'] += 1
                    
                    # Print result based on format
                    if output_format == "text" and not TQDM_AVAILABLE:
                        if banner:
                            print(f"[+] Port {port} is OPEN: {service} - {banner}")
                        else:
                            print(f"[+] Port {port} is OPEN: {service}")
                
                elif tcp_flags == 0x14:  # RST-ACK (port is closed)
                    if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:
                        print(f"[-] Port {port} is CLOSED")
                
                else:  # Other flags
                    if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:
                        print(f"[-] Port {port} is FILTERED")
            
            else:  # No response
                if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:
                    print(f"[-] Port {port} is FILTERED (no response)")
                    
        except Exception as e:
            if output_format == "text" and not TQDM_AVAILABLE:
                print(f"[-] Error scanning port {port}: {e}")
        finally:
            if update_progress_callback:
                update_progress_callback()
