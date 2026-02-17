#!/usr/bin/env python3
import ssl
import socket
import threading
from datetime import datetime

class TLSServer:
    def __init__(self, host='localhost', port=8443):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Force TLS 1.3
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Load server certificate and private key
        self.context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        
        # Enable client authentication (optional)
        # self.context.load_verify_locations(cafile='cert.pem')
        # self.context.verify_mode = ssl.CERT_REQUIRED
        
        # Set strong cipher suites (compatible with Python's ssl module)
        self.context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        print(f"TLS 1.3 Server configured on {host}:{port}")
        print(f"Supported cipher suites: {self.context.get_ciphers()}")
    
    def handle_client(self, client_socket, addr):
        """Handle individual client connections"""
        try:
            print(f"\n=== New Connection from {addr} ===")
            print(f"Connection time: {datetime.now()}")
            
            # Get TLS handshake information
            tls_socket = client_socket
            print(f"TLS Version: {tls_socket.version()}")
            print(f"Cipher: {tls_socket.cipher()}")
            
            # Send welcome message
            welcome = b"Welcome to TLS 1.3 Secure Server!"
            tls_socket.send(welcome)
            
            # Receive client message
            data = tls_socket.recv(1024)
            if data:
                print(f"Received from client: {data.decode()}")
                response = b"Message received securely via TLS 1.3!"
                tls_socket.send(response)
            
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            client_socket.close()
            print(f"Connection closed for {addr}")
    
    def start(self):
        """Start the TLS server"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.host, self.port))
            sock.listen(5)
            print(f"Server listening on {self.host}:{self.port}")
            
            try:
                while True:
                    client_socket, addr = sock.accept()
                    print(f"Accepting connection from {addr}")
                    
                    # Wrap socket with TLS
                    try:
                        tls_socket = self.context.wrap_socket(client_socket, server_side=True)
                        # Handle client in separate thread
                        client_thread = threading.Thread(
                            target=self.handle_client, 
                            args=(tls_socket, addr)
                        )
                        client_thread.daemon = True
                        client_thread.start()
                    except ssl.SSLError as e:
                        print(f"TLS handshake failed with {addr}: {e}")
                        client_socket.close()
                        
            except KeyboardInterrupt:
                print("\nServer shutting down...")
            finally:
                sock.close()

if __name__ == "__main__":
    server = TLSServer()
    server.start()
