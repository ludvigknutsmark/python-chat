# chat_client.py
import sys, socket, select, os, base64, getpass, time
import simplejson as json
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from mk_cert_files import *
from OpenSSL import SSL

#Own modules
from dh import *
from messencrypt import *
from sign import *
from SSLUtil import *

def chat_client(port, password):
    #As this is just a basic program to show encryption, signatures and
    #elliptic curve diffie-hellman some production features will obvious not exist
    #as for example an login/register which would solve some really important issues
    #with this program. As a public key not sent from the client before signing for example.

    #Create a password for the signature private key
    if password == None:
        while 1:
            password = getpass.getpass("Enter a password for your private key>")
            password_check = getpass.getpass("Enter it again>")
            if password == password_check:
                break
            else:
                print "Passwords does not match."

    host = '83.253.117.77'  
    #Get CA signed SSL certificate from server
    getCertificate()
    s = initSSLClient(9009)
    #Selecting the port for the chatroom to join.
    roomport = roomHandler(s)
    #SSL socket with the new port.
    getCertificate()
    s = initSSLClient(roomport)
    username = raw_input("Enter your chatalias> ")
    #Create the signature
    signMessage(s, username, password)
    #Generate key for encryption. If you are not "Hub", this key will be thrown.
    fernet_key = generateFernetKey()
    #Gets the fernet key for the end-to-end encryption
    fernet = diffieHellmanExchange(s,fernet_key)
    #is Hub, use the generated key.
    if fernet == 0:
        fernet = fernet_key
    fernet = base64.urlsafe_b64encode(fernet)

    #Now you can chat
    print 'Connected to remote host. Press :q for exiting the chat.'
    sys.stdout.write('['+username+'] '); sys.stdout.flush()

    while 1:
        socket_list = [sys.stdin, s]
        #Get the list sockets which are readable
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
                            sys.stdout.write('['+username+'] ')
                            sys.stdout.flush()
                        #You are not hub acting in diffie-hellman exchange
                        #decrypt the message
                        else:
                            ciphertext = data["message"].encode("utf8")
                            plaintext = decrypt(ciphertext, fernet)
                            sys.stdout.write('\n'+'['+data["dh"]+'] ' + plaintext)
                            sys.stdout.write('\n'+'['+username+'] ')
                            sys.stdout.flush()
                except:
                    continue
            else:
                try:
                    msg = raw_input()               
                #Handling exit of chat... 
                except KeyboardInterrupt:
                    sys.exit()       
                if msg.lower() == ':q':
                    s.close()
                    return chat_client(9009,password)
                
                #Encypt the message with the fernet key
                ciphertext = encrypt(msg, fernet)
                s.send(ciphertext)
                sys.stdout.write('['+username+'] ')
                sys.stdout.flush()
                
def roomHandler(s):
    port = 0
    name=""
    operation=""
    done = False
    try:
        while done == False:
            print "Define action: \n1. Create a room. \n2. Join a room. \n3. Get a list of all rooms.\n4. :q to quit."
            action = raw_input(">")
            if action.lower() == ":q":
                sys.exit()
            if action == "1":
                while True:
                    operation = "create"
                    name = raw_input("Name of the room>")
                    if name.lower() == ':q':
                        return roomHandler(s)
                    
                    #Check if that room already exists or the queue is full
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
                    if name.lower() == ':q':
                        return roomHandler(s)

                    jsonstr = {"name":name, "operation":operation}
                    s.send(json.dumps(jsonstr))
                    port = s.recv(4096)
                    if port == "0":
                        print "Room does not exist..."
                    else:
                        break
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
    except KeyboardInterrupt:
        sys.exit()
    
    return int(port)

if __name__ == "__main__":
    sys.exit(chat_client(9009, None))
