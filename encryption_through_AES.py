from Crypto.Cipher import AES
import base64
import os

# Generate a random 16-byte key
key = os.urandom(16)

def pad(data):
    """Padding to make text a multiple of 16 bytes."""
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

def unpad(data):
    """Remove padding."""
    return data[:-ord(data[-1])]

def encrypt_AES(plaintext, key):
    """Encrypt the plaintext using AES."""
    cipher = AES.new(key, AES.MODE_ECB)  # Using ECB mode
    ciphertext = cipher.encrypt(pad(plaintext).encode())
    return base64.b64encode(ciphertext).decode()

def decrypt_AES(ciphertext, key):
    """Decrypt the ciphertext using AES."""
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_text = unpad(cipher.decrypt(base64.b64decode(ciphertext)).decode())
    return decrypted_text

# Example Usage
plaintext = "Hello, this is a secure message!"
ciphertext = encrypt_AES(plaintext, key)
decrypted_text = decrypt_AES(ciphertext, key)

print("Original Text:", plaintext)
print("Encrypted Text:", ciphertext)
print("Decrypted Text:", decrypted_text)
