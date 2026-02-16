import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# =====================================================
# Generate ECC Key Pairs (Alice & Bob)
# =====================================================

alice_private = ec.generate_private_key(ec.SECP256R1())
alice_public = alice_private.public_key()

bob_private = ec.generate_private_key(ec.SECP256R1())
bob_public = bob_private.public_key()

# =====================================================
# ECDH Key Exchange
# =====================================================

alice_shared_key = alice_private.exchange(ec.ECDH(), bob_public)
bob_shared_key = bob_private.exchange(ec.ECDH(), alice_public)

# Derive AES key from shared secret
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(alice_shared_key)

# =====================================================
# Encrypt Message Using AES-GCM
# =====================================================

message = b"Secure ECC Encryption Message"
aad = b"authenticated data"

aesgcm = AESGCM(derived_key)
nonce = os.urandom(12)

ciphertext = aesgcm.encrypt(nonce, message, aad)

# =====================================================
# Decrypt Message
# =====================================================

aesgcm_decrypt = AESGCM(derived_key)
decrypted = aesgcm_decrypt.decrypt(nonce, ciphertext, aad)

print("Original Message:", message)
print("Encrypted Message:", ciphertext)
print("Decrypted Message:", decrypted)
