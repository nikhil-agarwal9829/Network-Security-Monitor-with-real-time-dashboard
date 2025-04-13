import webbrowser
import os

def open_npcap_download():
    print("Opening Npcap download page...")
    print("\nInstallation Instructions:")
    print("1. Download the Npcap installer from the website")
    print("2. Run the installer as Administrator")
    print("3. Follow the installation wizard with these settings:")
    print("   - Check 'Install Npcap in WinPcap API-compatible Mode'")
    print("   - Check 'Install Npcap Driver'")
    print("4. After installation, restart your computer")
    
    webbrowser.open("https://npcap.com/#download")

if __name__ == "__main__":
    open_npcap_download() 