"""
Input validation utilities
"""

import ipaddress
import os


class InputValidator:
    """Validates user inputs and system requirements"""
    
    @staticmethod
    def is_valid_ip(ip):
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_port(port):
        """Validate port number"""
        return 1 <= port <= 65535
    
    @staticmethod
    def is_admin():
        """Check if the script is running with administrator/root privileges"""
        try:
            if os.name == 'nt':  # Windows
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:  # Linux/Unix/Mac
                return os.geteuid() == 0
        except Exception:
            return False
    
    @staticmethod
    def validate_arguments(args, scapy_available=False):
        """
        Validate all command-line arguments
        
        Args:
            args: Parsed command-line arguments
            scapy_available (bool): Whether scapy is available
            
        Returns:
            list: List of error/warning messages
        """
        errors = []
        
        # Validate IP address
        if not InputValidator.is_valid_ip(args.target):
            errors.append(f"❌ Invalid IP address: {args.target}")
        
        # Validate threads
        if args.threads < 1:
            errors.append(f"❌ Thread count must be at least 1, got: {args.threads}")
        elif args.threads > 1000:
            errors.append(f"⚠️  WARNING: Thread count of {args.threads} is very high and may cause issues")
        
        # Validate timeout
        if args.timeout <= 0:
            errors.append(f"❌ Timeout must be positive, got: {args.timeout}")
        
        # Validate scan type with scapy availability
        if hasattr(args, 'type') and args.type != "connect" and not scapy_available:
            errors.append(f"❌ Scan type '{args.type}' requires Scapy. Install with: pip install scapy")
        
        # Check admin privileges for advanced scans
        if hasattr(args, 'type') and args.type != "connect" and not InputValidator.is_admin():
            errors.append(f"⚠️  WARNING: '{args.type}' scan requires administrator/root privileges")
        
        # Validate output file if specified
        if hasattr(args, 'output') and args.output:
            # Check if directory exists
            output_dir = os.path.dirname(args.output)
            if output_dir and not os.path.exists(output_dir):
                errors.append(f"❌ Output directory does not exist: {output_dir}")
        
        return errors
