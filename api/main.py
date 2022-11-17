from modules.crypto_module import encrypt, decrypt
from fastapi import FastAPI


app = FastAPI()


def validate(cipher):
    if not decrypt(cipher):
        return "PADDING ERROR"
    else:
        return "VALID CIPHER"


@app.get("/encrypt")
async def root(message):
    cipher = encrypt(message)
    return {"ciphertext": cipher}


@app.get("/decrypt")
async def root(key, cipher):
    message = decrypt(key, cipher)
    return {"message": message}


@app.get("/validate")
async def root(cipher):
    message = validate(cipher)
    return {"status": message}
