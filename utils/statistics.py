"""
Statistics generation and display
"""

from collections import Counter
from core.ports import HIGH_RISK_PORTS


class StatisticsGenerator:
    """Generates and formats scan statistics"""
    
    @staticmethod
    def generate_statistics(scan_results, total_ports, duration, start_port, end_port):
        """
        Generate comprehensive scan statistics
        
        Args:
            scan_results (list): List of scan results
            total_ports (int): Total number of ports scanned
            duration (float): Scan duration in seconds
            start_port (int): Starting port number
            end_port (int): Ending port number
            
        Returns:
            dict: Statistics dictionary
        """
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
        risky_ports = [r for r in scan_results if r["port"] in HIGH_RISK_PORTS and r["state"] == "open"]
        
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
    
    @staticmethod
    def print_statistics(stats):
        """
        Print formatted statistics
        
        Args:
            stats (dict): Statistics dictionary from generate_statistics()
        """
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
