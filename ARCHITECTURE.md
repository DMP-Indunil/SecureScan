# SecureScan - Modular Architecture

## Overview
SecureScan has been refactored from a 662-line monolithic file into a clean, modular architecture for better maintainability and extensibility.

## Directory Structure

```
SecureScan/
├── scanner.py              # Main entry point (246 lines)
├── requirements.txt        # Python dependencies
├── README.md              # Project documentation
├── .gitignore             # Git ignore rules
│
├── core/                  # Core functionality
│   ├── __init__.py       # Module exports
│   ├── ports.py          # Port definitions, scan types, service maps
│   └── network.py        # Network utilities (banner grabbing)
│
├── scanners/              # Scan implementations
│   ├── __init__.py       # Scanner exports
│   ├── connect_scan.py   # TCP Connect scanner
│   ├── syn_scan.py       # SYN/Half-open scanner
│   └── stealth_scan.py   # Stealth scanners (FIN/XMAS/NULL)
│
├── utils/                 # Utility functions
│   ├── __init__.py       # Utility exports
│   ├── validators.py     # Input validation
│   └── statistics.py     # Statistics generation
│
└── output/                # Output formatting
    ├── __init__.py       # Output exports
    ├── formatters.py     # Text output formatting
    └── exporters.py      # JSON/CSV export
```

## Module Responsibilities

### core/
**Purpose**: Fundamental definitions and low-level network operations

- `ports.py`: Defines ScanType enum, PortState enum, COMMON_PORTS dict, HIGH_RISK_PORTS set
- `network.py`: Contains `get_service_banner()` function for service identification

### scanners/
**Purpose**: Different scan technique implementations

- `connect_scan.py`: ConnectScanner class for TCP connect scans
- `syn_scan.py`: SynScanner class for SYN/half-open scans
- `stealth_scan.py`: StealthScanner class for FIN, XMAS, and NULL scans

Each scanner implements a `scan_port()` method with consistent interface.

### utils/
**Purpose**: Helper functions for validation and analysis

- `validators.py`: InputValidator class with methods for validating IP addresses, ports, and scan parameters
- `statistics.py`: StatisticsGenerator class for generating and displaying scan statistics

### output/
**Purpose**: Formatting and exporting results

- `formatters.py`: OutputFormatter class for terminal output with colors
- `exporters.py`: ResultExporter class for JSON and CSV export

### scanner.py
**Purpose**: Main entry point that orchestrates all modules

- Command-line argument parsing
- Input validation
- Scan execution with thread pool
- Result display and export
- Error handling

## Benefits of Modular Architecture

### 1. **Maintainability**
- Each file has a single, clear purpose
- Easy to locate specific functionality
- Changes are isolated to relevant modules

### 2. **Testability**
- Individual modules can be tested in isolation
- Mock dependencies easily for unit testing
- Clear interfaces between components

### 3. **Extensibility**
- Add new scan types by creating new scanner classes
- Add new export formats without touching core logic
- Easy to add new validation rules

### 4. **Code Reusability**
- Modules can be imported independently
- Common functionality centralized (e.g., banner grabbing)
- No code duplication

### 5. **Collaboration**
- Multiple developers can work on different modules
- Clear ownership of components
- Easier code reviews

## File Size Comparison

| Component | Lines |
|-----------|-------|
| Original scanner.py | 662 |
| **Refactored Total** | **~900** |
| New scanner.py | 246 |
| core/ports.py | 56 |
| core/network.py | 56 |
| scanners/connect_scan.py | 87 |
| scanners/syn_scan.py | 108 |
| scanners/stealth_scan.py | 105 |
| utils/validators.py | 99 |
| utils/statistics.py | 115 |
| output/formatters.py | 105 |
| output/exporters.py | 73 |

## Usage (Unchanged)

The command-line interface remains identical:

```bash
# Basic scan
python scanner.py --target 192.168.1.1 --ports 1-1000

# Advanced scan with export
python scanner.py -t 10.0.0.1 -p 1-1000 --threads 100 --output results.json --format json

# SYN scan (requires admin)
python scanner.py -t example.com -p 80,443 --type syn
```

## Testing

All functionality has been preserved and tested:

```bash
# Test basic scan
python scanner.py --target 127.0.0.1 --ports 1-100 --threads 50 --no-identify

# Test with larger range
python scanner.py --target 127.0.0.1 --ports 1-500 --threads 100 --no-identify

# Test JSON export
python scanner.py --target 127.0.0.1 --ports 80,443 --output test.json --format json
```

## Future Enhancements

The modular architecture makes it easy to add:

1. **New Scan Types**: Add a new file in `scanners/`
2. **Additional Output Formats**: Extend `output/exporters.py`
3. **More Statistics**: Add methods to `utils/statistics.py`
4. **Custom Validators**: Add rules to `utils/validators.py`
5. **Plugin System**: Create a plugins/ directory for user extensions

## Git Commits

- Commit `5256d0b`: Refactor into modular architecture
- Commit `ae599df`: Add .gitignore and clean up __pycache__

## Version

- **Version**: 2.0.0
- **Branch**: dev
- **Status**: Tested and working
