from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Generate RSA keys (Private and Public)
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

def encrypt_RSA(plaintext, public_key):
    """Encrypt the plaintext using RSA public key."""
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_data = cipher_rsa.encrypt(plaintext.encode())
    return base64.b64encode(encrypted_data).decode()

def decrypt_RSA(ciphertext, private_key):
    """Decrypt the ciphertext using RSA private key."""
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher_rsa.decrypt(base64.b64decode(ciphertext))
    return decrypted_data.decode()

# Example Usage
plaintext = "Hello, RSA encryption!"
ciphertext = encrypt_RSA(plaintext, public_key)
decrypted_text = decrypt_RSA(ciphertext, private_key)

print("Original Text:", plaintext)
print("Encrypted Text:", ciphertext)
print("Decrypted Text:", decrypted_text)
