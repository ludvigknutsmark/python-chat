import sys, os, base64
import simplejson as json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from messencrypt import encrypt
from messencrypt import generateFernetKey

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

    serialized_hub_public = hub_public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return sendKeyToClient(hub_shared, fernet_key, serialized_hub_public, salt)


def sendKeyToClient(shared_key, fernet_key, serialized_hub_public, salt):

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(shared_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(bytes(fernet_key)) + encryptor.finalize()
    #Send public, CT, IV and salt
    json_string = {"hub_public": serialized_hub_public, "ciphertext": base64.b64encode(ct), "iv": base64.b64encode(iv), "salt": base64.b64encode(salt)}
    return json.dumps(json_string)


def getKeyFromHub(client_private, public_cipher_iv):
    parsed = json.loads(public_cipher_iv)

    hub_serialized = parsed['hub_public'].encode('ascii')
    ct = base64.b64decode(parsed['ciphertext'])
    iv = base64.b64decode(parsed['iv'])
    salt = base64.b64decode(parsed['salt'])

    hub_public = load_pem_public_key(hub_serialized, backend=default_backend())
    shared_key = client_private.exchange(ec.ECDH(), hub_public)
    #The shared key needs to be 16 bytes (AES blocksize). So it's put through a KDF
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

def clientCreateKeys():
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    serialized_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'test')
    )
    file = open("ecdh/private.pem", "w")
    file.write(serialized_private)
    file.close()
    public_key = private_key.public_key()
    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serialized_public

def diffieHellmanExchange(s, fernet_key):
    dhDone = False
    while dhDone == False:
        serialized_public = ""
        fernet = 0
        #If you are a hub you can exit in the "blank state" with ctrl^c
        try:
            unparsed = s.recv(4096)
            data = json.loads(unparsed)
        except KeyboardInterrupt:
            sys.exit()

        if not data:
            print '\nDisconnected from chat server'
            sys.exit()
        else :
            if data["dh"] == "c":
                #Is client, create keys and send.                
                keyExchange(s)
            if data["dh"] == "h":
                #The client is the key hub.
                sendFernet(s, data, fernet_key)
                dhDone = True
            if data["dh"] == "c1":
                #get private DH key
                private_key = getPrivateECDHKey()
                fernet = getKeyFromHub(private_key, data["message"])
                dhDone = True
    return fernet


def getPrivateECDHKey():
    file = open("ecdh/private.pem", "r")
    serialized_private = ''.join(file.readlines())
    private_key = serialization.load_pem_private_key(
        serialized_private,
        #Could be None. Doesn't matter as the key will be overwritten for next ECDH-exchange so it's not a security risk.
        password=b'test',
        backend=default_backend()
        )
    return private_key

def keyExchange(s):
    serialized_public = clientCreateKeys()
    s.send(serialized_public)

def sendFernet(s, data, fernet_key):
    pub = data["message"].encode("utf8")
    client_public = serialization.load_pem_public_key(
        pub,
        backend=default_backend()
    )
    jsonstr = hubExchange(client_public, fernet_key)
    s.send(jsonstr)
