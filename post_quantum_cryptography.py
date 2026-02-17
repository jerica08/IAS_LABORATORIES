from liboqs import KeyEncapsulation, KeySignature

import secrets



# =====================================================

# Generate Public & Private Keys (Kyber512)

# =====================================================



kem = KeyEncapsulation("Kyber512")

public_key = kem.generate_keypair()

private_key = kem.export_secret_key()



print("Public Key Generated")

print("Private Key Generated")



# =====================================================

# Encrypt (Encapsulate) - Generate Shared Secret

# =====================================================



ciphertext, shared_secret_sender = kem.encap_secret(public_key)



print("\nCiphertext:", ciphertext)

print("Sender Shared Secret:", shared_secret_sender)



# =====================================================

# Decrypt (Decapsulate)

# =====================================================



kem2 = KeyEncapsulation("Kyber512")

kem2.secret_key = private_key

shared_secret_receiver = kem2.decap_secret(ciphertext)



print("\nReceiver Shared Secret:", shared_secret_receiver)



# =====================================================

# Verify

# =====================================================



if shared_secret_sender == shared_secret_receiver:

    print("\n Shared secrets match!")

else:

    print("\n Shared secrets do NOT match!")