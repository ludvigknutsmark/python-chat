from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json

def encrypt(plaintext, key):
    #Create a Fernet block and use it for encryption.
    fblock = Fernet(key)
    return fblock.encrypt(bytes(plaintext))

def decrypt(ciphertext, key):
    fblock = Fernet(key)
    return fblock.decrypt(bytes(ciphertext))

def generateFernetKey():
    #Generate the fernet key and put it through a KDF (for AES cipher compability)
    salt = os.urandom(16)
    fernet_key = Fernet.generate_key()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    fernet_key = kdf.derive(fernet_key)
    return fernet_key
