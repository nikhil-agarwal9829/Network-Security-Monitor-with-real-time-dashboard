from scapy.all import sniff, wrpcap, conf, show_interfaces
import sys
import os
import time

def list_interfaces():
    print("\nAvailable Network Interfaces:")
    show_interfaces()
    return conf.ifaces

def packet_callback(packet):
    print(f"Captured packet of length: {len(packet)}")
    return packet

def capture(iface_name):
    print(f"\nStarting capture on interface: {iface_name}")
    print("Capturing packets... Please wait...")
    print("(If no packets appear, try opening a web browser to generate traffic)")
    
    try:
        # Capture packets with a filter to ensure we get IP packets
        packets = sniff(
            iface=iface_name,
            count=50,  # Capture 50 packets
            timeout=15,  # Timeout after 15 seconds
            prn=packet_callback,
            filter="ip"  # Only capture IP packets
        )
        
        if len(packets) > 0:
            filename = f"captured_packets_{int(time.time())}.pcap"
            wrpcap(filename, packets)
            print(f"\nSuccess! {len(packets)} packets captured and saved as '{filename}'")
            print("You can now analyze these packets using the web interface (dash4.py)")
            return True
        else:
            print("\nNo packets were captured. Please try:")
            print("1. Selecting a different interface")
            print("2. Checking if your network connection is active")
            print("3. Generating some network traffic (e.g., browse a website)")
            return False
            
    except Exception as e:
        print(f"\nError during capture: {e}")
        print("\nTroubleshooting steps:")
        print("1. Try selecting a different interface")
        print("2. Check if the interface is active and connected")
        print("3. Try generating some network traffic")
        return False

if __name__ == "__main__":
    print("\n=== Network Packet Capture Tool ===")
    print("This tool will capture network packets and save them for analysis.")
    
    # Get list of interfaces
    interfaces = list_interfaces()
    if not interfaces:
        print("No network interfaces found!")
        sys.exit(1)
    
    print("\nAvailable interfaces:")
    interface_list = list(interfaces)
    for i, iface in enumerate(interface_list):
        print(f"{i}. {iface}")
    
    while True:
        try:
            choice = int(input("\nEnter the interface number (0, 1, 2, etc.): "))
            if 0 <= choice < len(interface_list):
                # Try to generate some traffic
                print("\nTip: Open a web browser and visit a website while capturing to generate traffic")
                if capture(interface_list[choice]):
                    break
                else:
                    retry = input("\nWould you like to try again? (y/n): ")
                    if retry.lower() != 'y':
                        break
            else:
                print("Invalid interface number!")
        except ValueError:
            print("Please enter a valid number!")
        except KeyboardInterrupt:
            print("\nCapture cancelled by user.")
            break
