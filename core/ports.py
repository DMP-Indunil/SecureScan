"""
Port definitions and service mappings
"""

from enum import Enum

# Scan types
class ScanType(Enum):
    CONNECT = "connect"  # Basic TCP connect scan
    SYN = "syn"          # SYN scan (half-open)
    FIN = "fin"          # FIN scan
    XMAS = "xmas"        # XMAS scan (FIN, PSH, URG)
    NULL = "null"        # NULL scan

# Port states
class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"

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

# High-risk ports for security assessment
HIGH_RISK_PORTS = {21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5900, 8080}
