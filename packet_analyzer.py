#!/usr/bin/env python3

import json
import time
from collections import defaultdict, deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from threading import Thread, Lock

class PacketAnalyzer:
    def __init__(self):
        self.data_file = "security_data.json"
        self.lock = Lock()
        self.security_data = {
            "total_packets": 0,
            "suspicious_count": 0,
            "recent_threats": [],
            "packet_history": []
        }
        
        # Analysis parameters
        self.syn_flood_threshold = 100  # SYN packets per second
        self.packet_size_threshold = 1500  # Bytes
        self.suspicious_ports = {22, 23, 3389}  # SSH, Telnet, RDP
        
        # Tracking variables
        self.syn_count = defaultdict(int)
        self.last_syn_check = time.time()
        self.packet_window = deque(maxlen=1000)
        
        # Load existing data if available
        self.load_data()
        
        # Start background tasks
        Thread(target=self.periodic_save, daemon=True).start()
        Thread(target=self.analyze_trends, daemon=True).start()

    def load_data(self):
        try:
            with open(self.data_file, 'r') as f:
                self.security_data = json.load(f)
        except FileNotFoundError:
            self.save_data()

    def save_data(self):
        with self.lock:
            with open(self.data_file, 'w') as f:
                json.dump(self.security_data, f, indent=4)

    def periodic_save(self):
        while True:
            self.save_data()
            time.sleep(60)  # Save every minute

    def analyze_trends(self):
        while True:
            with self.lock:
                if len(self.packet_window) > 0:
                    avg_size = sum(p['size'] for p in self.packet_window) / len(self.packet_window)
                    if avg_size > self.packet_size_threshold:
                        self.add_threat(f"High average packet size: {avg_size:.2f} bytes")
            time.sleep(10)

    def add_threat(self, threat_desc):
        with self.lock:
            timestamp = datetime.now().isoformat()
            self.security_data["recent_threats"].append({
                "timestamp": timestamp,
                "description": threat_desc
            })
            self.security_data["suspicious_count"] += 1
            
            # Keep only last 100 threats
            if len(self.security_data["recent_threats"]) > 100:
                self.security_data["recent_threats"].pop(0)

    def packet_callback(self, packet):
        if IP not in packet:
            return

        with self.lock:
            self.security_data["total_packets"] += 1
            
            packet_info = {
                "timestamp": datetime.now().isoformat(),
                "src": packet[IP].src,
                "dst": packet[IP].dst,
                "size": len(packet),
                "protocol": "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
            }
            
            # Add to packet history
            self.packet_window.append(packet_info)
            self.security_data["packet_history"].append(packet_info)
            if len(self.security_data["packet_history"]) > 1000:
                self.security_data["packet_history"].pop(0)

            # Check for suspicious ports
            if TCP in packet:
                dst_port = packet[TCP].dport
                if dst_port in self.suspicious_ports:
                    self.add_threat(f"Access attempt to suspicious port {dst_port}")

                # SYN flood detection
                if packet[TCP].flags & 0x02:  # SYN flag
                    self.syn_count[packet[IP].src] += 1
                    current_time = time.time()
                    
                    if current_time - self.last_syn_check >= 1:
                        for ip, count in self.syn_count.items():
                            if count > self.syn_flood_threshold:
                                self.add_threat(f"Possible SYN flood from {ip}: {count} SYN packets/sec")
                        self.syn_count.clear()
                        self.last_syn_check = current_time

    def start(self):
        print("Starting packet capture and analysis...")
        try:
            sniff(prn=self.packet_callback, store=0)
        except PermissionError:
            print("Error: This script requires administrator/root privileges to capture packets.")
            exit(1)

if __name__ == "__main__":
    analyzer = PacketAnalyzer()
    analyzer.start() 