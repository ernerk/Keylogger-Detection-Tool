# Keylogger Detection Tool

A sophisticated tool for detecting potential keyloggers and suspicious processes on your system.

## Features

- Real-time monitoring of system processes
- Detection of keyboard hooks and suspicious activities
- System resource usage analysis (CPU, Memory, Disk I/O)
- Detailed reporting in JSON and CSV formats
- User-friendly graphical interface

## Screenshots

### Main Interface - Process Monitoring
![Process Monitoring](../images/process_monitoring.png)

The main interface shows:
- List of suspicious processes with their details
- PID (Process ID)
- Process Name
- CPU Usage
- Memory Usage
- Disk I/O
- Suspicion Level

### System Analysis
![System Analysis](../images/system_analysis.png)

The System Analysis tab displays:
- Real-time CPU usage graphs
- Memory usage monitoring
- Disk I/O activity tracking
- Historical data visualization

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ernerk/KeyLogger.git
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application with administrator privileges:
```bash
python keylogger_detector.py
```

2. Click "Start Scanning" to begin monitoring
3. Use the different tabs to view:
   - Suspicious Processes
   - Keyboard Hooks
   - System Analysis
4. Generate reports using the "Generate Report" button

## Features in Detail

### Process Detection
- Monitors all running processes
- Calculates suspicion level based on multiple factors:
  - Process name and characteristics
  - Resource usage patterns
  - File access patterns
  - Network activity
  - System hooks

### Keyboard Hook Detection
- Monitors for keyboard hook installation
- Detects potential keylogging activity
- Tracks keyboard event handling

### System Analysis
- Real-time resource monitoring
- Historical data tracking
- Performance impact analysis
- Suspicious behavior pattern detection

## Reports

The tool generates two types of reports:
1. JSON Report (keylogger_report.json)
   - Detailed process information
   - Hook detection results
   - System analysis data
   
2. CSV Report (keylogger_report.csv)
   - Suspicious process list
   - Resource usage statistics
   - Easy to import into spreadsheet software

## Security Notes

- Run with administrator privileges for full functionality
- Keep the tool updated for best detection rates
- Use in conjunction with other security tools
- Monitor system regularly for suspicious activities

## Requirements

- Windows Operating System
- Python 3.6 or higher
- Administrator privileges
- Required Python packages (see requirements.txt)

## Disclaimer

This tool is for educational and security research purposes only. Use responsibly and in accordance with applicable laws and regulations. 