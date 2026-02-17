#!/usr/bin/env python3
"""
Wireshark Traffic Analysis Guide for TLS 1.3
This script provides instructions and tools for analyzing encrypted TLS 1.3 traffic
"""

import subprocess
import time
import ssl
import socket
from datetime import datetime

class WiresharkAnalyzer:
    def __init__(self):
        self.capture_file = "tls_traffic_capture.pcap"
        self.interface = "Ethernet"  # Change based on your network interface
        
    def print_wireshark_setup_guide(self):
        """Print comprehensive Wireshark setup guide"""
        print("=" * 60)
        print("WIRESHARK TLS 1.3 TRAFFIC ANALYSIS GUIDE")
        print("=" * 60)
        
        print("\n1. INSTALL WIRESHARK:")
        print("   Download from: https://www.wireshark.org/download.html")
        print("   Install with Npcap for Windows packet capture")
        
        print("\n2. CONFIGURE TLS DECRYPTION:")
        print("   • Go to Edit > Preferences > Protocols > TLS")
        print("   • Set '(Pre)-Master-Secret log filename' to:")
        print("     C:\\Users\\USER\\Desktop\\ssl_keys.log")
        
        print("\n3. SET UP SSL KEY LOGGING:")
        print("   • Set environment variable:")
        print("     set SSLKEYLOGFILE=C:\\Users\\USER\\Desktop\\ssl_keys.log")
        print("   • Or add to Python script before TLS connections:")
        print("     os.environ['SSLKEYLOGFILE'] = 'ssl_keys.log'")
        
        print("\n4. CAPTURE FILTERS:")
        print("   • Basic TLS filter: tls")
        print("   • Specific port: tcp.port == 8443")
        print("   • TLS 1.3 only: tls.version == \"TLS 1.3\"")
        print("   • Handshake only: tls.handshake")
        
        print("\n5. DISPLAY FILTERS:")
        print("   • Client Hello: tls.handshake.type == 1")
        print("   • Server Hello: tls.handshake.type == 2")
        print("   • Encrypted data: tls.app_data")
        print("   • Certificate: tls.handshake.certificate")
        
        print("\n6. TLS 1.3 HANDSHAKE FIELDS TO ANALYZE:")
        print("   • tls.handshake.type - Message type")
        print("   • tls.handshake.extensions_supported - Extensions")
        print("   • tls.handshake.ciphersuites - Cipher suites")
        print("   • tls.record.content_type - Record type")
        print("   • tls.record.version - TLS version")
        
    def generate_test_traffic(self):
        """Generate test TLS traffic for analysis"""
        print("\n" + "=" * 40)
        print("GENERATING TEST TLS TRAFFIC")
        print("=" * 40)
        
        print("Starting TLS traffic generation...")
        print("Make sure Wireshark is capturing on interface:", self.interface)
        print("Use filter: tcp.port == 8443")
        
        # Generate multiple TLS connections
        for i in range(3):
            print(f"\n--- Connection {i+1} ---")
            try:
                # Create TLS context
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
                
                # Connect and send data
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    with context.wrap_socket(sock, server_hostname='localhost') as tls_socket:
                        tls_socket.connect(('localhost', 8443))
                        
                        # Send test data
                        test_message = f"Test message {i+1} at {datetime.now()}"
                        tls_socket.send(test_message.encode())
                        
                        # Receive response
                        response = tls_socket.recv(1024)
                        print(f"Response: {response.decode()}")
                        
                        time.sleep(1)  # Pause between connections
                        
            except Exception as e:
                print(f"Connection {i+1} failed: {e}")
        
        print("\nTest traffic generation complete!")
        print("Stop Wireshark capture and save the file for analysis.")
    
    def analyze_tls_fields(self):
        """Print detailed TLS field analysis guide"""
        print("\n" + "=" * 50)
        print("TLS 1.3 PROTOCOL FIELD ANALYSIS")
        print("=" * 50)
        
        print("\nHANDSHAKE MESSAGES:")
        print("1. Client Hello (0x01):")
        print("   - Client random value")
        print("   - Supported cipher suites")
        print("   - Supported extensions")
        print("   - Key share values")
        
        print("\n2. Server Hello (0x02):")
        print("   - Server random value")
        print("   - Selected cipher suite")
        print("   - Selected extensions")
        print("   - Server key share")
        
        print("\n3. Encrypted Extensions (0x08):")
        print("   - Server configuration")
        print("   - Application layer protocols")
        
        print("\n4. Certificate (0x0B):")
        print("   - Server certificate chain")
        print("   - Certificate verification")
        
        print("\n5. Certificate Verify (0x0F):")
        print("   - Signature over handshake hash")
        print("   - Proves certificate ownership")
        
        print("\n6. Finished (0x14):")
        print("   - Verify handshake integrity")
        print("   - Start encrypted communication")
        
        print("\nAPPLICATION DATA:")
        print("• Content Type: 0x17 (Application Data)")
        print("• Encrypted with negotiated cipher suite")
        print("• Protected by both encryption and MAC")
        
        print("\nSECURITY ANALYSIS POINTS:")
        print("• Verify only TLS 1.3 is used")
        print("• Check for strong cipher suites")
        print("• Ensure perfect forward secrecy")
        print("• Validate certificate chain")
        print("• Monitor for protocol downgrade attacks")

def main():
    analyzer = WiresharkAnalyzer()
    
    while True:
        print("\n" + "=" * 50)
        print("WIRESHARK TLS 1.3 ANALYSIS TOOL")
        print("=" * 50)
        print("1. Setup Guide")
        print("2. Generate Test Traffic")
        print("3. Field Analysis Guide")
        print("4. Exit")
        
        choice = input("\nSelect option (1-4): ")
        
        if choice == '1':
            analyzer.print_wireshark_setup_guide()
        elif choice == '2':
            analyzer.generate_test_traffic()
        elif choice == '3':
            analyzer.analyze_tls_fields()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
