"""
Output formatting utilities
"""

from colorama import Fore, Style


class OutputFormatter:
    """Format and display scan results"""
    
    @staticmethod
    def print_header(target, port_range, scan_type, threads):
        """
        Print scan header information
        
        Args:
            target (str): Target IP address
            port_range (str): Port range being scanned
            scan_type (str): Type of scan
            threads (int): Number of threads
        """
        print("\n" + "="*60)
        print(f"{Fore.CYAN}🔍 SecureScan - Network Port Scanner{Style.RESET_ALL}".center(70))
        print("="*60)
        print(f"{Fore.YELLOW}Target:{Style.RESET_ALL}      {target}")
        print(f"{Fore.YELLOW}Ports:{Style.RESET_ALL}       {port_range}")
        print(f"{Fore.YELLOW}Scan Type:{Style.RESET_ALL}   {scan_type}")
        print(f"{Fore.YELLOW}Threads:{Style.RESET_ALL}     {threads}")
        print("="*60 + "\n")
    
    @staticmethod
    def print_port_result(port, state, service, banner=None):
        """
        Print individual port scan result
        
        Args:
            port (int): Port number
            state (str): Port state
            service (str): Service name
            banner (str, optional): Service banner
        """
        # Color coding by state
        if state == "open":
            state_color = Fore.GREEN
            state_symbol = "✓"
        elif state == "closed":
            state_color = Fore.RED
            state_symbol = "✗"
        elif state == "filtered":
            state_color = Fore.YELLOW
            state_symbol = "?"
        else:  # open|filtered
            state_color = Fore.CYAN
            state_symbol = "~"
        
        # Format output
        port_str = f"{port:5d}"
        state_str = f"{state_color}{state_symbol} {state:15s}{Style.RESET_ALL}"
        service_str = f"{service:20s}"
        
        output = f"Port {port_str} | {state_str} | {service_str}"
        
        if banner:
            # Truncate long banners
            banner_preview = banner[:50] + "..." if len(banner) > 50 else banner
            output += f" | {Fore.LIGHTBLACK_EX}{banner_preview}{Style.RESET_ALL}"
        
        print(output)
    
    @staticmethod
    def print_results(results, show_closed=False):
        """
        Print all scan results
        
        Args:
            results (list): List of scan result dictionaries
            show_closed (bool): Whether to show closed ports
        """
        print(f"\n{Fore.CYAN}📋 Scan Results:{Style.RESET_ALL}\n")
        print(f"{'Port':<10} | {'State':<20} | {'Service':<25} | {'Banner':<50}")
        print("-" * 110)
        
        open_results = [r for r in results if r["state"] == "open"]
        filtered_results = [r for r in results if r["state"] in ["filtered", "open|filtered"]]
        closed_results = [r for r in results if r["state"] == "closed"]
        
        # Print open ports first
        for result in open_results:
            OutputFormatter.print_port_result(
                result["port"],
                result["state"],
                result["service"],
                result.get("banner")
            )
        
        # Print filtered ports
        for result in filtered_results:
            OutputFormatter.print_port_result(
                result["port"],
                result["state"],
                result["service"],
                result.get("banner")
            )
        
        # Print closed ports if requested
        if show_closed:
            for result in closed_results:
                OutputFormatter.print_port_result(
                    result["port"],
                    result["state"],
                    result["service"]
                )
        
        # Summary
        print("-" * 110)
        print(f"\n{Fore.GREEN}✓ Open:{Style.RESET_ALL} {len(open_results)}", end="")
        if filtered_results:
            print(f" | {Fore.CYAN}~ Filtered:{Style.RESET_ALL} {len(filtered_results)}", end="")
        print(f" | {Fore.RED}✗ Closed:{Style.RESET_ALL} {len(closed_results)}")
