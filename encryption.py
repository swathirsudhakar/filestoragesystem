from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import os

# Generate RSA Key Pair
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print("RSA Keys Generated Successfully!")

# Encrypt File Using AES + RSA
def encrypt_file(file_path, public_key_path):
    # Generate a random AES key
    aes_key = get_random_bytes(16)
    
    # Encrypt the AES key using RSA
    recipient_key = RSA.import_key(open(public_key_path).read())
    rsa_cipher = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    # Encrypt the file data using AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    
    with open(file_path, "rb") as f:
        file_data = f.read()
    
    ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

    # Save encrypted data
    with open(file_path + ".enc", "wb") as f:
        f.write(enc_aes_key + cipher_aes.nonce + tag + ciphertext)
    
    print("File Encrypted Successfully!")

# Decrypt File Using AES + RSA
def decrypt_file(encrypted_file_path, private_key_path):
    with open(encrypted_file_path, "rb") as f:
        enc_data = f.read()

    private_key = RSA.import_key(open(private_key_path).read())
    rsa_cipher = PKCS1_OAEP.new(private_key)

    enc_aes_key = enc_data[:256]  # First 256 bytes are RSA encrypted AES key
    nonce = enc_data[256:272]  # Next 16 bytes are nonce
    tag = enc_data[272:288]  # Next 16 bytes are authentication tag
    ciphertext = enc_data[288:]  # Rest is encrypted data

    # Decrypt AES key
    aes_key = rsa_cipher.decrypt(enc_aes_key)

    # Decrypt file data
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    decrypted_file_path = encrypted_file_path.replace(".enc", "_decrypted.txt")
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)

    print("File Decrypted Successfully!")

# Run this function once to generate RSA keys
if not os.path.exists("public.pem") or not os.path.exists("private.pem"):
    generate_rsa_keys()

# Add this section to actually call encrypt or decrypt functions
if __name__ == "__main__":
    # Encrypt a file
    encrypt_file("myfile.txt", "public.pem")
    # Or decrypt a file if needed
    # decrypt_file("myfile.txt.enc", "private.pem")
