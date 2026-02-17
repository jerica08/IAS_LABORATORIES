#!/usr/bin/env python3
"""
Zero-Knowledge Proof (ZKP) Implementations
This script demonstrates various ZKP concepts and implementations
"""

import hashlib
import random
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class SchnorrZKP:
    """
    Schnorr Zero-Knowledge Proof Implementation
    Demonstrates knowledge of discrete logarithm without revealing it
    """
    
    def __init__(self):
        # Use a large prime for demonstration (in practice, use standardized parameters)
        self.p = 2**255 - 19  # Curve25519 prime field
        self.g = 2  # Generator
        self.generate_keys()
    
    def generate_keys(self):
        """Generate private and public keys"""
        self.private_key = secrets.randbelow(self.p - 2) + 1
        self.public_key = pow(self.g, self.private_key, self.p)
        print(f"Schnorr Keys Generated:")
        print(f"  Private key: {self.private_key}")
        print(f"  Public key: {self.public_key}")
    
    def prove(self, message):
        """Create a ZKP for the given message"""
        print(f"\n--- Creating ZKP for message: '{message}' ---")
        
        # Step 1: Generate random commitment
        k = secrets.randbelow(self.p - 2) + 1
        r = pow(self.g, k, self.p)  # Commitment
        
        # Step 2: Create challenge (hash of message and commitment)
        challenge_data = f"{message}{r}".encode()
        e = int(hashlib.sha256(challenge_data).hexdigest(), 16) % self.p
        
        # Step 3: Calculate response
        s = (k - e * self.private_key) % (self.p - 1)
        
        print(f"  Commitment (r): {r}")
        print(f"  Challenge (e): {e}")
        print(f"  Response (s): {s}")
        
        return r, e, s
    
    def verify(self, message, r, e, s):
        """Verify the ZKP"""
        print(f"\n--- Verifying ZKP for message: '{message}' ---")
        
        # Calculate expected commitment
        expected_r = (pow(self.g, s, self.p) * pow(self.public_key, e, self.p)) % self.p
        
        print(f"  Received commitment: {r}")
        print(f"  Expected commitment: {expected_r}")
        
        # Verify
        is_valid = r == expected_r
        print(f"  Verification result: {'✓ VALID' if is_valid else '✗ INVALID'}")
        return is_valid

class FiatShamirZKP:
    """
    Fiat-Shamir Zero-Knowledge Proof Implementation
    Demonstrates knowledge of square root modulo composite number
    """
    
    def __init__(self):
        self.generate_parameters()
    
    def generate_parameters(self):
        """Generate parameters for Fiat-Shamir protocol"""
        # For demonstration, use small primes (in practice, use large secure primes)
        self.p = 1019  # Prime
        self.q = 1031  # Prime
        self.n = self.p * self.q  # Composite number
        
        # Generate secret (square root)
        self.secret = secrets.randbelow(self.n - 2) + 2
        self.public_value = (self.secret * self.secret) % self.n
        
        print(f"Fiat-Shamir Parameters:")
        print(f"  p: {self.p}")
        print(f"  q: {self.q}")
        print(f"  n (p*q): {self.n}")
        print(f"  Secret: {self.secret}")
        print(f"  Public value (s² mod n): {self.public_value}")
    
    def prove(self):
        """Create Fiat-Shamir ZKP"""
        print(f"\n--- Creating Fiat-Shamir ZKP ---")
        
        # Step 1: Generate random commitment
        r = secrets.randbelow(self.n - 2) + 1
        x = (r * r) % self.n  # Commitment
        
        # Step 2: Generate random challenge bit
        c = random.randint(0, 1)
        
        # Step 3: Calculate response
        if c == 0:
            y = r  # Reveal r
        else:
            y = (r * self.secret) % self.n  # Reveal r*s
        
        print(f"  Commitment (x): {x}")
        print(f"  Challenge bit (c): {c}")
        print(f"  Response (y): {y}")
        
        return x, c, y
    
    def verify(self, x, c, y):
        """Verify Fiat-Shamir ZKP"""
        print(f"\n--- Verifying Fiat-Shamir ZKP ---")
        
        # Calculate expected commitment
        if c == 0:
            expected_x = (y * y) % self.n
        else:
            expected_x = (y * y * pow(self.public_value, -1, self.n)) % self.n
        
        print(f"  Received commitment: {x}")
        print(f"  Expected commitment: {expected_x}")
        
        # Verify
        is_valid = x == expected_x
        print(f"  Verification result: {'✓ VALID' if is_valid else '✗ INVALID'}")
        return is_valid

class RSAZKP:
    """
    RSA-based Zero-Knowledge Proof
    Demonstrates knowledge of private key without revealing it
    """
    
    def __init__(self):
        self.generate_rsa_keys()
    
    def generate_rsa_keys(self):
        """Generate RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        print(f"RSA Keys Generated:")
        print(f"  Key size: 2048 bits")
        print(f"  Public exponent: 65537")
    
    def prove_knowledge(self, message):
        """Prove knowledge of private key using blind signature"""
        print(f"\n--- RSA ZKP for message: '{message}' ---")
        
        # Hash the message
        message_hash = hashlib.sha256(message.encode()).digest()
        
        # Create blind signature (simplified ZKP)
        blinding_factor = secrets.randbelow(2**256)
        
        # Sign with private key (proving knowledge)
        signature = self.private_key.sign(
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        # Verify with public key
        try:
            self.public_key.verify(
                signature,
                message_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            is_valid = True
            print(f"  Signature verified: ✓ VALID")
        except Exception as e:
            is_valid = False
            print(f"  Signature verification failed: ✗ INVALID")
        
        return signature, is_valid

def interactive_zkp_demo():
    """Interactive demonstration of ZKP concepts"""
    print("=" * 60)
    print("ZERO-KNOWLEDGE PROOF INTERACTIVE DEMONSTRATION")
    print("=" * 60)
    
    while True:
        print("\nSelect ZKP Protocol:")
        print("1. Schnorr ZKP (Discrete Logarithm)")
        print("2. Fiat-Shamir ZKP (Square Root)")
        print("3. RSA-based ZKP")
        print("4. ZKP Theory Explanation")
        print("5. Exit")
        
        choice = input("\nEnter choice (1-5): ")
        
        if choice == '1':
            schnorr = SchnorrZKP()
            message = input("Enter message to prove: ")
            r, e, s = schnorr.prove(message)
            schnorr.verify(message, r, e, s)
            
        elif choice == '2':
            fiat_shamir = FiatShamirZKP()
            x, c, y = fiat_shamir.prove()
            fiat_shamir.verify(x, c, y)
            
        elif choice == '3':
            rsa_zkp = RSAZKP()
            message = input("Enter message to sign: ")
            signature, valid = rsa_zkp.prove_knowledge(message)
            
        elif choice == '4':
            print_zkp_theory()
            
        elif choice == '5':
            break
            
        else:
            print("Invalid choice. Please try again.")

def print_zkp_theory():
    """Print ZKP theoretical concepts"""
    print("\n" + "=" * 50)
    print("ZERO-KNOWLEDGE PROOF THEORY")
    print("=" * 50)
    
    print("\nDEFINITION:")
    print("A zero-knowledge proof is a method by which one party (the prover)")
    print("can prove to another party (the verifier) that they know a value x,")
    print("without conveying any information apart from the fact that they know x.")
    
    print("\nTHREE PROPERTIES:")
    print("1. Completeness: If the statement is true, the honest verifier will be")
    print("   convinced by an honest prover.")
    print("2. Soundness: If the statement is false, no cheating prover can convince")
    print("   the honest verifier (except with negligible probability).")
    print("3. Zero-Knowledge: If the statement is true, the verifier learns nothing")
    print("   except that the statement is true.")
    
    print("\nTYPES OF ZKPS:")
    print("• Interactive ZKPs: Prover and verifier interact multiple times")
    print("• Non-interactive ZKPs: Single message from prover to verifier")
    print("• Statistical ZKPs: Zero-knowledge holds with high probability")
    print("• Computational ZKPs: Zero-knowledge holds against polynomial-time adversaries")
    
    print("\nAPPLICATIONS:")
    print("• Authentication: Prove identity without revealing credentials")
    print("• Cryptocurrencies: Privacy-preserving transactions")
    print("• Voting systems: Prove eligibility without revealing identity")
    print("• Password authentication: Prove knowledge without sending password")
    print("• Blockchain: Privacy-preserving smart contracts")

if __name__ == "__main__":
    interactive_zkp_demo()
