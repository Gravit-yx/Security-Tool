# Network Security Tool

A Python-based network monitoring tool that detects suspicious activity on a network. This tool monitors incoming traffic and detects:
- Port scans
- High traffic volumes from specific IPs
- Suspicious packets based on predefined criteria

## Features
- **Port Scan Detection**: Alerts when an IP scans multiple unique ports.
- **High Traffic Volume Detection**: Flags IPs that exceed a traffic threshold.
- **Suspicious Packet Logging**: Logs packets that meet suspicious criteria to a file for further analysis.

## Technologies Used
- **Python**: Core programming language for the tool.
- **Scapy**: Used for packet sniffing and analysis.
- **Logging**: Logs alerts and suspicious activity to a file for record-keeping.

## Requirements
- Python 3.x
- Scapy library (`pip install scapy`)

## How to Run
1. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/<your-username>/<repository-name>.git
   cd <repository-name>
2. Install the required dependencies:
    pip install scapy
3. Run the script with administrator/root privileges:
    sudo python3 security_tool.py
4. The script will start monitoring network traffic and display alerts in the terminal. Detected suspicious activity will also be logged in suspicious_activity.log.

## Sample Alerts
Port Scan Detection:
Port scan detected from IP: 192.168.1.100, Scanned ports: [22, 80, 443, 8080, 3306]

High Traffic Volume Detection:
High traffic volume detected from IP: 185.125.190.75

Suspicious Packet:
Suspicious Packet - Source: 10.0.0.1, Destination: 192.168.1.1

## Customization
Thresholds: Adjust thresholds for port scans and traffic volume by modifying the relevant parts of the script.
- Port scan threshold: Change the value in this line:
  if len(scan_tracker[ip_src]) > 10:  # Adjust threshold as needed
- High traffic threshold: Update this value:
  if traffic_counter[ip_src] > 20:  # Adjust threshold as needed
Suspicious Packet Criteria: Modify the logic in log_suspicious_packet() to define what constitutes a suspicious packet.

 
