from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def load_aes_key():
    with open('../secret_aes.key', 'rb') as f:
        return f.read()
    
def encrypt_file(data):
    key = load_aes_key()
    cipher = AES.new(key, AES.MODE_CBC)

    # pad data to be multiple of 16
    pad_len = 16 - (len(data) % 16)
    padded_data = data + bytes([pad_len] * pad_len)

    # encrypt the data and prepend IV
    ciphertext = cipher.encrypt(padded_data)  # FIXED: removed the list and multiplication

    return cipher.iv + ciphertext