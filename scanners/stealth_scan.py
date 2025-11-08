"""
Stealth scan implementations (FIN, XMAS, NULL)
"""

from core.ports import PortState, ScanType, COMMON_PORTS

# Try importing scapy
try:
    from scapy.all import IP, TCP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Try importing tqdm for progress bar
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


class StealthScanner:
    """Stealth scan (FIN, XMAS, NULL) implementation"""
    
    @staticmethod
    def scan_port(ip, port, scan_type=ScanType.FIN, output_format="text", scan_results=None,
                  scan_results_lock=None, open_ports_count=None, update_progress_callback=None):
        """
        Perform stealth scan on a single port
        
        Args:
            ip (str): Target IP address
            port (int): Port to scan
            scan_type (ScanType): Type of stealth scan (FIN/XMAS/NULL)
            output_format (str): Output format (text/json/csv)
            scan_results (list): Shared results list
            scan_results_lock (Lock): Thread lock for results
            open_ports_count (dict): Counter for open ports
            update_progress_callback (callable): Progress update function
        """
        if not SCAPY_AVAILABLE:
            if output_format == "text" and not TQDM_AVAILABLE:
                print(f"[-] Scapy not available, cannot perform {scan_type.value} scan on port {port}")
            if update_progress_callback:
                update_progress_callback()
            return
            
        try:
            # Set appropriate TCP flags based on scan type
            if scan_type == ScanType.FIN:
                flags = "F"  # FIN scan
            elif scan_type == ScanType.XMAS:
                flags = "FPU"  # XMAS scan (FIN, PSH, URG)
            elif scan_type == ScanType.NULL:
                flags = ""  # NULL scan (no flags)
            else:
                if update_progress_callback:
                    update_progress_callback()
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
                
                if scan_results is not None and scan_results_lock is not None:
                    with scan_results_lock:
                        scan_results.append(scan_result)
                        if open_ports_count is not None:
                            open_ports_count['count'] += 1
                
                if output_format == "text" and not TQDM_AVAILABLE:
                    print(f"[+] Port {port} is possibly OPEN: {service} (no response)")
            
            elif response.haslayer(TCP):
                # If we get a RST response, port is closed
                if response.getlayer(TCP).flags & 0x04:  # Check for RST flag
                    if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:
                        print(f"[-] Port {port} is CLOSED")
                else:
                    # Other responses are unexpected for these scan types
                    if output_format == "text" and not TQDM_AVAILABLE and port % 50 == 0:
                        print(f"[-] Port {port} returned unexpected response")
                        
        except Exception as e:
            if output_format == "text" and not TQDM_AVAILABLE:
                print(f"[-] Error scanning port {port} with {scan_type.value} scan: {e}")
        finally:
            if update_progress_callback:
                update_progress_callback()
