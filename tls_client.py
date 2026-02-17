#!/usr/bin/env python3
import ssl
import socket
from datetime import datetime

class TLSClient:
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context()
        
        # Force TLS 1.3
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # For testing with self-signed certificates
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        
        # Set strong cipher suites (compatible with Python's ssl module)
        self.context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        print(f"TLS 1.3 Client configured for {host}:{port}")
    
    def connect_and_communicate(self):
        """Connect to TLS server and perform secure communication"""
        try:
            print(f"\n=== Connecting to TLS Server ===")
            print(f"Connection time: {datetime.now()}")
            
            # Create socket and wrap with TLS
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                with self.context.wrap_socket(sock, server_hostname=self.host) as tls_socket:
                    tls_socket.connect((self.host, self.port))
                    
                    # Display TLS connection details
                    print(f"✓ Connected to {self.host}:{self.port}")
                    print(f"TLS Version: {tls_socket.version()}")
                    print(f"Cipher Suite: {tls_socket.cipher()}")
                    print(f"Server Certificate: {tls_socket.getpeercert()}")
                    
                    # Receive welcome message
                    welcome = tls_socket.recv(1024)
                    print(f"Server says: {welcome.decode()}")
                    
                    # Send message to server
                    message = "Hello from TLS 1.3 Client!"
                    tls_socket.send(message.encode())
                    print(f"Sent: {message}")
                    
                    # Receive response
                    response = tls_socket.recv(1024)
                    print(f"Server response: {response.decode()}")
                    
                    print("✓ TLS 1.3 handshake completed successfully!")
                    
        except ssl.SSLError as e:
            print(f"TLS Error: {e}")
        except ConnectionRefusedError:
            print("Connection refused. Is the server running?")
        except Exception as e:
            print(f"Error: {e}")
    
    def analyze_handshake(self):
        """Analyze TLS handshake details"""
        print(f"\n=== TLS 1.3 Handshake Analysis ===")
        print("TLS 1.3 Improvements over TLS 1.2:")
        print("• Round-trip time reduced from 2 to 1 (0-RTT)")
        print("• Forward secrecy for all handshakes")
        print("• No RSA key exchange (only DHE/ECDHE)")
        print("• Encrypted SNI (ESNI) support")
        print("• Simplified cipher suite negotiation")
        print("• Removed MD5 and SHA-1 support")
        print("• Mandatory authentication")
        print("• Removed renegotiation")

if __name__ == "__main__":
    client = TLSClient()
    client.analyze_handshake()
    client.connect_and_communicate()
