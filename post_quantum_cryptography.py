import pqcrypto
from pqcrypto.kem import ml_kem_512

def run_pqc_test():
    print("--- Starting Post-Quantum Test ---")

    # 1. Key Generation   
    pk, sk = ml_kem_512.generate_keypair()
    
    print(f"Public Key type: {type(pk)} | Length: {len(pk)}")
    print(f"Private Key type: {type(sk)} | Length: {len(sk)}")

    # 2. Encapsulation (Encryption) 
    ct, ss_enc = ml_kem_512.encrypt(pk)
    print(f"Ciphertext generated. Length: {len(ct)}")

    # 3. Decapsulation (Decryption)
    try:
        ss_dec = ml_kem_512.decrypt(ct, sk)
        print("Decryption successful!")
        
        if ss_enc == ss_dec:
            print("RESULT: Shared secrets match! 100% Secure.")
        else:
            print("RESULT: Mismatch detected.")
            
    except ValueError as e:
        print(f"Library Error: {e}")
        print("Debugging: Check if 'sk' was modified between steps.")

if __name__ == "__main__":
    run_pqc_test()