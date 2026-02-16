import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

# Sample message
data = b"This is a secret message"
aad = b"authenticated but not encrypted data"

# ----------------------------
# AES-GCM Encryption
# ----------------------------
def aes_gcm_encrypt():
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    start = time.time()
    ciphertext = aesgcm.encrypt(nonce, data, aad)
    end = time.time()

    decrypted = aesgcm.decrypt(nonce, ciphertext, aad)

    return end - start, decrypted


# ----------------------------
# ChaCha20 Encryption
# ----------------------------
def chacha20_encrypt():
    key = ChaCha20Poly1305.generate_key()
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)

    start = time.time()
    ciphertext = chacha.encrypt(nonce, data, aad)
    end = time.time()

    decrypted = chacha.decrypt(nonce, ciphertext, aad)

    return end - start, decrypted


# Run Both
aes_time, aes_decrypted = aes_gcm_encrypt()
chacha_time, chacha_decrypted = chacha20_encrypt()

print("AES-GCM Decrypted:", aes_decrypted)
print("ChaCha20 Decrypted:", chacha_decrypted)

print("\nPerformance Comparison:")
print("AES-GCM Time:", aes_time)
print("ChaCha20 Time:", chacha_time)
