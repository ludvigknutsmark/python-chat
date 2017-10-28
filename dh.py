import os
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from messencrypt import generateFernetKey

def diffie():
    fernet_key = generateFernetKey()

    #Is generated when connecting to server
    client_private = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    client_public = client_private.public_key()

    #Generates the shared_key and returns the encrypted fernet_key
    jstr = hubExchange(client_public, fernet_key)

    #Generates the shared_key and decrypts the fernet_key
    f = getKeyFromHub(client_private, jstr)

    print f


def hubExchange(client_public, fernet_key):
    #Generate a private key for use in the exchange
    hub_private = ec.generate_private_key(
        ec.SECP384R1(), default_backend()
    )
    hub_public = hub_private.public_key()
    hub_shared = hub_private.exchange(ec.ECDH(), client_public)

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    hub_shared = kdf.derive(bytes(hub_shared))

    serialized_hub_public = client_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return sendKeyToClient(hub_shared, fernet_key, serialized_hub_public)


def sendKeyToClient(shared_key, fernet_key, serialized_hub_public):
    iv = os.urandom(16)
    #All partys need to do this.
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(fernet_key)) + encryptor.finalize()
    #Skicka CT OCH IV
    print serialized_hub_public
    print type(serialized_hub_public)
    json_string = {"hub_public": serialized_hub_public, "ciphertext": base64.encodestring(ct), "iv": base64.encodestring(iv)}
    return json.dumps(json_string)


def getKeyFromHub(client_private, public_cipher_iv):
    parsed = json.loads(public_cipher_iv)

    hub_unserialized = parsed['hub_public'].encode("utf-8")
    ct = base64.decodestring(parsed['ciphertext'])
    iv = base64.decodestring(parsed['iv'])

    hub_public = serialization.load_pem_public_key(
        hub_unserialized,
        backend=default_backend()
    )

    shared_key = client_private.exchange(ec.ECDH(), hub_public)
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    shared_key = kdf.derive(bytes(shared_key))

    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    fernet = decryptor.update(ct) + decryptor.finalize()

    return fernet

diffie()
