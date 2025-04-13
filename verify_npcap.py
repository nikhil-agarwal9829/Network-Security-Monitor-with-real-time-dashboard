from scapy.all import conf

def verify_npcap():
    print("Checking Npcap installation...")
    print("\nDetected Network Interfaces:")
    print("-" * 50)
    
    if hasattr(conf, 'ifaces'):
        for iface in conf.ifaces:
            print(f"Interface: {iface}")
        print("\nNpcap appears to be installed correctly!")
    else:
        print("Error: No network interfaces detected.")
        print("Npcap might not be installed correctly.")
        print("Please make sure to:")
        print("1. Install Npcap as Administrator")
        print("2. Restart your computer")
        print("3. Run this script again")

if __name__ == "__main__":
    verify_npcap() 