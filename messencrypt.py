from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def messencrypt():
    #This key should be generated from diffie-hellman
    key = Fernet.generate_key()
    plaintext = "Hello World!"
    c = encrypt(plaintext, key)
    p = decrypt(c, key)
    print p

def encrypt(plaintext, key):
    fblock = Fernet(key)
    return fblock.encrypt(bytes(plaintext))

def decrypt(ciphertext, key):
    fblock = Fernet(key)
    return fblock.decrypt(bytes(ciphertext))

def generateFernetKey():
    #Is the key that HUB generates first thing when elected hub.
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
