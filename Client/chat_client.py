# chat_client.py
import sys, socket, select
import base64
import simplejson as json
import getpass
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#Own modules
from dh import clientCreateKeys
from dh import getKeyFromHub
from dh import hubExchange
from messencrypt import generateFernetKey
from messencrypt import encrypt
from messencrypt import decrypt
from sign import createSerializedKeys
from sign import createSignature
from sign import verifySignature



def chat_client(port, password):
    #As this is just a basic program to show encryption, signatures and
    #elliptic curve diffie-hellman some production features will obvious not exist
    #as for example an login/register which would solve some really important issues
    #with this program. As a public key not sent from the client before signing for example.


    #Create a password for the signature private key
    if password == None:
        while 1:
            password = getpass.getpass("Enter a password for the private key>")
            password_check = getpass.getpass("Enter it again>")
            if password == password_check:
                break;
            else:
                print "Passwords does not match."

    host = '83.253.117.77'

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    #connect to server
    try :
        s.connect((host, port))
    except :
        print 'Unable to connect'
        sys.exit()

    #Selecting the port for the chatroom to join.
    roomport = roomHandler(s)

    #Resetting the socket s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, roomport))
    except:
        print "unable to connect to:", roomport
        sys.exit()

    #enter your username for the chat.
    username = raw_input("Enter your chatalias> ")
    #Create the signature
    sign(s, username, password)

    #Generate key for encryption. If you are not "Hub", this key will be thrown.
    fernet_key = generateFernetKey()
    #Gets the fernet key for end-to-end encryption
    fernet = diffieHellmanExchange(s,fernet_key)

    #is Hub, use the generated key.
    if fernet == 0:
        fernet = fernet_key

    fernet = base64.urlsafe_b64encode(fernet)

    #Now you can chat...
    print 'Connected to remote host. Press q for exiting the chat.'
    sys.stdout.write('['+username+'] '); sys.stdout.flush()

    while 1:
        socket_list = [sys.stdin, s]
        # Get the list sockets which are readable
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
        for sock in read_sockets:
            if sock == s:
                unparsed = sock.recv(4096)
                try:
                    data = json.loads(unparsed)

                    if not data :
                            print '\nDisconnected from chat server'
                            sys.exit()
                    else :
                        if data["dh"] == "h":
                            sendFernet(s, data, base64.urlsafe_b64decode(fernet))
                        #server message
                        if data["dh"] == "server":
                            sys.stdout.write('\n' + data["message"])
                            sys.stdout.write('['+username+'] ');
                            sys.stdout.flush()

                        #You are not hub acting in diffie-hellman exchange
                        #decrypt the message
                        else:
                            ciphertext = data["message"].encode("utf8")
                            #print ciphertext
                            plaintext = decrypt(ciphertext, fernet)
                            sys.stdout.write('\n'+'['+data["dh"]+'] ' + plaintext)
                            sys.stdout.write('\n'+'['+username+'] ');
                            sys.stdout.flush()
                except:
                    continue;
            else:
                msg = raw_input()
                #Handling exit of chat...
                if msg.lower() == 'q':
                    s.close()
                    return chat_client(9009,password)
                ciphertext = encrypt(msg, fernet)
                s.send(ciphertext)
                sys.stdout.write('['+username+'] ');
                sys.stdout.flush();


def roomHandler(s):
    port = 0
    name=""
    operation=""
    done = False
    while done == False:
        print "Define action: \n1. Create a room. \n2. Join a room. \n3. Get a list of all rooms.\n4. q to quit."
        action = raw_input(">")
        if action.lower() == "q":
            sys.exit()
        if action == "1":
            while True:
                operation = "create"
                name = raw_input("Name of the room>")

                #Check if that name already exists
                jsonstr = {"name":name, "operation":operation}

                s.send(json.dumps(jsonstr))

                condition = s.recv(4096)
                if condition == "exist":
                    print "Chatroom already exists"
                elif condition == "full":
                    print "Chatroom capacity met."

                else:
                    print "Room created successfully"
                    jsonstr = {"name":name, "operation":"join"}
                    s.send(json.dumps(jsonstr))
                    port = s.recv(4096)
                    break
            done = True

        if action == "2":
            while 1:
                operation = "join"
                name = raw_input("Name of the room>")
                if name.lower() == 'q':
                    return roomHandler(s)

                jsonstr = {"name":name, "operation":operation}
                s.send(json.dumps(jsonstr))
                port = s.recv(4096)
                if port == "0":
                    print "Room does not exist..."
                else:
                    break;
            done = True

        if action == "3":
            operation = "list"
            jsonstr = {"name": name, "operation": operation}
            s.send(json.dumps(jsonstr))
            roomlist = s.recv(4096)
            print "#################ROOMS##################"
            for room in roomlist.split():
                print "----------------------------------------"
                print room

            print "----------------------------------------"
            print "########################################"

    return int(port)


def sign(s, username, password):
    signatureDone = False
    while signatureDone == False:
        socket_list = [sys.stdin, s]
        serialized_public = ""
        fernet = 0
        # Get the list sockets which are readable
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
        for sock in read_sockets:
            if sock == s:
                unparsed = sock.recv(4096)
                data = json.loads(unparsed)
                if not data :
                    print '\nDisconnected from chat server'
                    sys.exit()
                else :
                    #First step in DH, is client
                    if data["dh"] == "sign":
                        createSerializedKeys(password);
                        signature = createSignature("private.pem", bytes(data["message"]))
                        public_key = getPublicKey("public.pem")
                        json_str = {"username": username, "public_key": public_key, "signature": base64.b64encode(signature)}
                        s.send(json.dumps(json_str))
                        signatureDone = True


def diffieHellmanExchange(s, fernet_key):
    dhDone = False
    while dhDone == False:
        socket_list = [sys.stdin, s]
        serialized_public = ""
        fernet = 0
        # Get the list sockets which are readable
        read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
        for sock in read_sockets:
            if sock == s:
                # incoming message from remote server, s
                unparsed = sock.recv(4096)
                data = json.loads(unparsed)
                if not data:
                    print '\nDisconnected from chat server'
                    sys.exit()
                else :
                    #First step in DH, is client
                    if data["dh"] == "c":
                        print "Creating DH keys...\n"
                        keyExchange(s)
                    if data["dh"] == "h":
                        print "Is hub\n"
                        sendFernet(s, data, fernet_key)
                        dhDone = True
                    if data["dh"] == "c1":
                        #get private DH key
                        file = open("ecdh/private.pem", "r")
                        serialized_private = ''.join(file.readlines())
                        private_key = serialization.load_pem_private_key(
                            serialized_private,
                            #Can be none. Doesn't matter as the key will be destroyed for next ECDH-exchange.
                            password=b'test',
                            backend=default_backend()
                        )
                        #get key
                        fernet = getKeyFromHub(private_key, data["message"])
                        dhDone = True
    return fernet

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

def getPublicKey(pathToPublicKey):
    file = open(pathToPublicKey, "r")
    serialized_public = ''.join(file.readlines())
    return serialized_public

if __name__ == "__main__":
    sys.exit(chat_client(9009, None))
