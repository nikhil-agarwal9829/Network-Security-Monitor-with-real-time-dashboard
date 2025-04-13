# Network Security Monitor

A real-time network security monitoring system that captures and analyzes network traffic for potential security threats.

## Features

- Real-time packet capture and analysis
- Live security dashboard with threat detection
- Network activity visualization
- Threat distribution analysis
- Security scoring system

## Components

1. **packet_analyzer.py**: Captures and analyzes network packets in real-time
2. **dash_security.py**: Web-based dashboard for visualizing security data
3. **security_data.json**: Data exchange file between analyzer and dashboard

## Requirements

- Python 3.8+
- See requirements.txt for Python dependencies
- Administrator/root privileges for packet capture

## Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Detailed Usage Guide

### 1. Start Packet Analyzer

First, run the packet analyzer with administrator privileges:
```
python packet_analyzer.py
```

This will:
- Start capturing network packets
- Analyze packets for security threats
- Create and update `security_data.json` file containing:
  ```json
  {
    "total_packets": 0,
    "suspicious_count": 0,
    "recent_threats": [],
    "packet_history": [
      {
        "timestamp": "2024-xx-xx xx:xx:xx",
        "src": "source_ip",
        "dst": "dest_ip",
        "size": "packet_size",
        "protocol": "TCP/UDP"
      }
    ]
  }
  ```

### 2. Launch Security Dashboard

After the packet analyzer is running and creating the JSON file, start the dashboard:
```
python dash_security.py
```

### 3. View Dashboard

Open your web browser and navigate to:
```
http://127.0.0.1:8052
```

You will see:
- Real-time packet statistics
- Threat detection alerts
- Network activity graphs
- Security score
- Threat distribution charts

## Additional Components

### Development and Testing Files

1. **capture_packets.py**
   - Standalone packet capture utility
   - Used for testing packet capture functionality
   - Creates .pcap files for offline analysis

2. **dash3.py** and **dash4.py**
   - Development versions of the dashboard
   - Contains experimental features and layouts
   - Used for testing different visualization approaches
   - Can be used as alternatives to dash_security.py for different visualization needs

### Data Files

- **security_data.json**: Real-time data exchange file
- **.pcap files**: Captured packet data in standard packet capture format

## Security Notes

- The packet analyzer requires administrator/root privileges to capture network packets
- This tool is for educational and network monitoring purposes only
- Always follow your organization's security policies and applicable laws when monitoring network traffic
- Captured packet data (.pcap files) may contain sensitive information - handle with care 