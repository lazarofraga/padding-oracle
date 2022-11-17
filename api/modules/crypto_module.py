import hashlib
import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto import Random

mode = AES.MODE_CBC
block_size = 16
password = "password123"
key = hashlib.sha256(password.encode()).digest()
iv = b'\x81\x915\x1d\xce\x97<|\xd0\x1c\xe2P"\xe2+"'


def generate_key(password):
    return hashlib.sha256(password.encode()).digest()


def encrypt(plaintext):
    cipher = AES.new(key, mode, iv)
    encrypted_message = cipher.encrypt(
        pad(plaintext.encode("ascii"), block_size))
    encrypted_message = base64.urlsafe_b64encode(encrypted_message)
    return encrypted_message


def decrypt(encrypted_message, password=password):
    print(iv)
    key = generate_key(password)
    cipher = AES.new(key, mode, iv)
    encrypted_message = base64.urlsafe_b64decode(encrypted_message)
    try:
        decrypted_text = unpad(cipher.decrypt(encrypted_message), block_size)
    except ValueError:
        return False
    return decrypted_text


if __name__ == "__main__":
    message = "This is your plaintext"
    print(message)
    encrypted_message = base64.b64encode(encrypt(key, mode, message))
    print(encrypted_message)
    print(decrypt(key, mode, base64.b64decode(encrypted_message)).decode())
