# Network Packet Analyzer

This packet analyzer captures and analyzes network traffic in real-time, feeding data to a security dashboard.

## Setup

1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the packet analyzer (requires administrator/root privileges):
   ```bash
   sudo python packet_analyzer.py
   ```

## Features

- Real-time packet capture and analysis
- Detection of suspicious port access
- SYN flood attack detection
- Packet size anomaly monitoring
- Continuous updates to security_data.json for dashboard integration

## Data Output

The analyzer writes to `security_data.json` with the following structure:
```json
{
    "total_packets": 0,
    "suspicious_count": 0,
    "recent_threats": [],
    "packet_history": []
}
```

## Note

This tool requires administrator/root privileges to capture packets. Run with caution in production environments. 