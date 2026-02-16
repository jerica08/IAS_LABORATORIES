from phe import paillier

def homomorphic_demo():
    print("--- Starting Paillier Homomorphic Encryption Demo ---")

    # 1. Key Generation
    public_key, private_key = paillier.generate_paillier_keypair()
    print("Keys generated successfully.")

    # 2. Encrypt two numbers
    num1 = 50
    num2 = 75
    
    encrypted_num1 = public_key.encrypt(num1)
    encrypted_num2 = public_key.encrypt(num2)
    
    print(f"Encrypted {num1} and {num2}.")

    # 3. Perform computation ON encrypted data (The "Magic" part)
    # We add the two encrypted objects together without decrypting them first
    encrypted_sum = encrypted_num1 + encrypted_num2
    print("Performed addition on encrypted data (without decryption).")

    # 4. Decrypt the result to verify
    decrypted_sum = private_key.decrypt(encrypted_sum)
    print(f"Decrypted Result: {decrypted_sum}")

    if decrypted_sum == (num1 + num2):
        print("Success! Homomorphic property verified.")
    else:
        print("Error: The sum does not match.")

if __name__ == "__main__":
    homomorphic_demo()