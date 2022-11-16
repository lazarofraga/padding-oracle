import hashlib
import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto import Random

mode = AES.MODE_CBC
block_size = 16


def encrypt(key, plaintext, mode=mode):
    rnd = Random.new()
    iv = rnd.read(block_size)
    cipher = AES.new(key, mode, iv)
    encrypted_message = cipher.encrypt(pad(plaintext.encode(), block_size))
    return iv + encrypted_message


def decrypt(key,encrypted_message, mode=mode):
    iv = encrypted_message[:block_size]
    encrypted_message = encrypted_message[block_size:]
    print(iv)
    print(encrypted_message)
    cipher = AES.new(key, mode, iv)
    decrypted_text = unpad(cipher.decrypt(encrypted_message), block_size)
    return decrypted_text


if __name__ == "__main__":
    message = "This is your plaintext"
    password = "password"
    password = password.encode()
    key = hashlib.sha256(password).digest()
    print(message)
    encrypted_message = base64.b64encode(encrypt(key, mode, message))
    print(encrypted_message)
    print(decrypt(key, mode, base64.b64decode(encrypted_message)).decode())
