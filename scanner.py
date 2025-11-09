#!/usr/bin/env python3
"""
SecureScan - Advanced Network Port Scanner
A modular, multi-threaded port scanner with multiple scan techniques

Author: SecureScan Team
Version: 2.0.0
License: MIT
"""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Import core modules
from core.ports import ScanType, PortState, COMMON_PORTS
from core.network import get_service_banner

# Import scanners
from scanners.connect_scan import ConnectScanner
from scanners.syn_scan import SynScanner
from scanners.stealth_scan import StealthScanner

# Import utilities
from utils.validators import InputValidator
from utils.statistics import StatisticsGenerator

# Import output handlers
from output.formatters import OutputFormatter
from output.exporters import ResultExporter


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="SecureScan - Advanced Network Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.1 --ports 1-1000
  %(prog)s -t scanme.nmap.org -p 80,443,8080 --identify
  %(prog)s -t 10.0.0.1 -p 1-65535 --threads 100 --type syn
  %(prog)s -t 192.168.1.1 -p 1-1000 --output results.json --format json
  %(prog)s -t example.com -p 20-25,80,443 --type xmas --no-progress

Scan Types:
  connect  - TCP Connect scan (no special privileges required)
  syn      - SYN/Half-open scan (requires admin/root)
  fin      - FIN stealth scan (requires admin/root)
  xmas     - XMAS stealth scan (requires admin/root)
  null     - NULL stealth scan (requires admin/root)

Note: SYN, FIN, XMAS, and NULL scans require administrator/root privileges.
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                        help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', required=True,
                        help='Port specification (e.g., 80, 1-1000, 22,80,443)')
    parser.add_argument('--type', choices=['connect', 'syn', 'fin', 'xmas', 'null'],
                        default='connect',
                        help='Scan type (default: connect)')
    parser.add_argument('--threads', type=int, default=50,
                        help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=float, default=1.0,
                        help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('--identify', action='store_true',
                        help='Attempt to identify services by banner grabbing')
    parser.add_argument('--no-identify', dest='identify', action='store_false',
                        help='Disable service identification (faster scanning)')
    parser.add_argument('--output', type=str,
                        help='Output file path')
    parser.add_argument('--format', choices=['json', 'csv', 'text'],
                        default='text',
                        help='Output format (default: text)')
    parser.add_argument('--show-closed', action='store_true',
                        help='Show closed ports in output')
    parser.add_argument('--no-progress', action='store_true',
                        help='Disable progress bar')
    
    parser.set_defaults(identify=True)
    
    return parser.parse_args()


def parse_port_specification(port_spec):
    """Parse port specification into list of ports"""
    ports = []
    parts = port_spec.split(',')
    
    for part in parts:
        part = part.strip()
        if '-' in part:
            start, end = part.split('-')
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    
    return sorted(set(ports))


def get_scanner(scan_type):
    """Get appropriate scanner class based on scan type"""
    scanner_map = {
        'connect': ConnectScanner,
        'syn': SynScanner,
        'fin': StealthScanner,
        'xmas': StealthScanner,
        'null': StealthScanner
    }
    return scanner_map.get(scan_type, ConnectScanner)


def perform_scan(target, ports, scan_type, threads, timeout, identify_services, show_progress):
    """Perform port scan with specified parameters"""
    results = []
    scanner_class = get_scanner(scan_type)
    
    if show_progress:
        pbar = tqdm(total=len(ports), desc="Scanning ports", unit="port",
                   bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]')
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_port = {}
        
        for port in ports:
            if scan_type == 'connect':
                future = executor.submit(scanner_class.scan_port, target, port, timeout, identify_services)
            elif scan_type == 'syn':
                future = executor.submit(scanner_class.scan_port, target, port, timeout, identify_services)
            else:
                future = executor.submit(scanner_class.scan_port, target, port, timeout, scan_type)
            
            future_to_port[future] = port
        
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"\n❌ Error scanning port {port}: {e}")
            
            if show_progress:
                pbar.update(1)
    
    if show_progress:
        pbar.close()
    
    results.sort(key=lambda x: x['port'])
    return results


def main():
    """Main entry point"""
    try:
        args = parse_arguments()
        
        # Validate inputs
        validator = InputValidator()
        errors = validator.validate_arguments(args)
        
        if errors:
            print("\n❌ Validation Errors:")
            for error in errors:
                print(f"   • {error}")
            sys.exit(1)
        
        try:
            ports = parse_port_specification(args.ports)
        except ValueError as e:
            print(f"❌ Invalid port specification: {e}")
            sys.exit(1)
        
        port_range = f"{min(ports)}-{max(ports)}" if len(ports) > 1 else str(ports[0])
        OutputFormatter.print_header(args.target, port_range, args.type.upper(), args.threads)
        
        start_time = time.time()
        results = perform_scan(
            target=args.target,
            ports=ports,
            scan_type=args.type,
            threads=args.threads,
            timeout=args.timeout,
            identify_services=args.identify,
            show_progress=not args.no_progress
        )
        duration = time.time() - start_time
        
        if args.format == 'text':
            OutputFormatter.print_results(results, show_closed=args.show_closed)
        
        stats = StatisticsGenerator.generate_statistics(
            scan_results=results,
            total_ports=len(ports),
            duration=duration,
            start_port=min(ports),
            end_port=max(ports)
        )
        StatisticsGenerator.print_statistics(stats)
        
        if args.output:
            if args.format in ['json', 'csv']:
                success = ResultExporter.export_results(results, args.format, args.output)
                if success:
                    print(f"\n✅ Results exported to {args.output}")
                else:
                    print(f"\n❌ Failed to export results")
            else:
                with open(args.output, 'w') as f:
                    f.write(f"SecureScan Results\n")
                    f.write(f"Target: {args.target}\n")
                    f.write(f"Ports: {port_range}\n")
                    f.write(f"Scan Type: {args.type}\n")
                    f.write(f"Duration: {duration:.2f}s\n\n")
                    
                    for result in results:
                        f.write(f"Port {result['port']:5d} | {result['state']:15s} | {result['service']}\n")
                        if result.get('banner'):
                            f.write(f"  Banner: {result['banner']}\n")
                
                print(f"\n✅ Results exported to {args.output}")
        
        print("\n✨ Scan completed successfully!\n")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
