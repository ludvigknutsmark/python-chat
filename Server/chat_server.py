# chat_server.py
import sys, socket, select, base64, os
import threading
from threading import Lock
import simplejson as json
from sign import verifySignature
import Queue

#ssl
from mk_cert_files import *
from OpenSSL import SSL

#x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

def verify_cb(conn, cert, errnum, depth, ok):
    # This obviously has to be updated
    #print 'Got certificate: %s' % cert.get_subject()
    return ok

def main():
    #create server certificates.
    createServerCert()
    #Defines which port that should be accessible
    q = Queue.Queue()
    for i in range(9010, 9015):
        q.put(i)
    chat_handler(q)

#JSON = {nameOfRoom, passwordToRoom, operation: create} - create a thread
#JSON = {nameOfRoom, operation: search} - return port number of room
#JSON = {operation:list} - return all rooms
def chat_handler(queue):
    HOST = ''
    SOCKET_LIST = []
    RECV_BUFFER = 4096
    PORT = 9009
    HubElector = 0
    threadName = 0
    #Creates a dictionary for port and servername
    roomDict = {}

    #START SIGNING THREAD
    signThread = threading.Thread(target=signCertThread,)
    signThread.daemon = True
    signThread.start()

    #Init a SSL socket
    ctx = initSSL()
    server_socket = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', PORT))
    server_socket.listen(10)
    SOCKET_LIST.append(server_socket)

    done = False
    while done == False:
        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
        for sock in ready_to_read:
            #New connection
            if sock == server_socket:
                sockfd, addr = server_socket.accept()
                SOCKET_LIST.append(sockfd)
            else:
                try:
                    unparsed = sock.recv(RECV_BUFFER)
                    data = json.loads(unparsed)
                    if data:
                        if data["operation"] == "create":
                            #Check if room already exists
                            if data["name"] in roomDict:
                                sock.send("exist")
                            else:
                                port = queue.get()
                                #Create thread for chat_server and add to rooms
                                threadName = threading.Thread(target=chat_server, args = (port, queue,roomDict, data["name"]))
                                #Check Queue status
                                if queue.empty() == False:
                                    sock.send("create")
                                    roomDict[data["name"]] = port
                                    threadName.daemon = True
                                    threadName.start()
                                    threadName += 1
                                else:
                                    sock.send("full")

                        if data["operation"] == "join":
                            try:
                                port = roomDict[data["name"]]
                            except:
                                port = 0
                            sock.send(str(port))

                        if data["operation"] == "list":
                            #get list of all server rooms
                            roomlist = " "
                            for key in roomDict:
                                roomlist+=key + " "
                            sock.send(str(roomlist))

                    else:
                        # remove the socket that's broken
                        print "removing\n"
                        if sock in SOCKET_LIST:
                            SOCKET_LIST.remove(sock)
                # exception
                except:
                    continue

    server_socket.close()

def chat_server(PORT, queue, roomDict, name):
    HOST = ''
    SOCKET_LIST = []
    RECV_BUFFER = 4096
    HubElector = 0
    HUBSOCK = ''
    mutex = Lock()
    #Creates a dictionary with addresses and usernames
    userDict = {}

    #Init and create SSL socket
    ctx = initSSL()
    server_socket = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('', PORT))
    server_socket.listen(10)
    SOCKET_LIST.append(server_socket)

    print "Chat server started on port " + str(PORT)

    chatDone = False
    while chatDone == False:
        # get the list sockets which are ready to be read through select
        # 4th arg, time_out  = 0 : poll and never block
        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)

        for sock in ready_to_read:
            # a new connection request recieved
            if sock == server_socket:
                sockfd, addr = server_socket.accept()
                #s.connect(('localhost', port))          
                SOCKET_LIST.append(sockfd)

                #Verify the signature of the client
                #IMPORTANT!!! The public key should be authenticated with a login/register, where a user generates a key pair
                #and saves that key to the database, which the server will then get.

                #server receives username
                #getPublicKey(username) --sql query.

                #In this basic example the sender will send the public key for testing purposes.
                check = createAnVerifySignature(sockfd, addr, userDict)

                if HubElector != 0:
                    #Preventing hub socket from hadnling data from two sockets
                    mutex.acquire()
                    keyExchange(HUBSOCK, sockfd, server_socket)
                    mutex.release()
                
                #Electing hub
                if HubElector == 0:
                    HUBSOCK = sockfd
                    HubElector = 1

                print "Client (%s, %s) connected" % addr

                broadcast(SOCKET_LIST, server_socket, sockfd, "server", "[%s] entered our chatting room\n" % userDict[addr])

            else:
                try:
                    #Broadcast the data sent by the client
                    data = sock.recv(RECV_BUFFER)
                    if data:
                        broadcast(SOCKET_LIST, server_socket, sock, userDict[(sock.getpeername())], data)
                    else:    
                        #Chat room is empty. Quit the thread and put the port back in the queue
                        if len(SOCKET_LIST) == 1:
                            chatDone = True
                        #Socket who disconnected was the Hub, elect new hub by finding the first valid.
                        if sock == HUBSOCK:
                            HUBSOCK = electNewHub(SOCKET_LIST, server_socket)

                        #Redundancy, remove the sock cause it's probably broken.
                        SOCKET_LIST.remove(sock)
                        broadcast(SOCKET_LIST, server_socket, sock, "server", "Client (%s) is offline\n" % userDict[sock.getpeername()])
                        userDict.pop(sock.getpeername(), None)
                except:
                    SOCKET_LIST.remove(sock)
                    broadcast(SOCKET_LIST, server_socket, sock, "server" ,"Client (%s) is offline\n" % userDict[sock.getpeername()])
                    userDict.pop(sock.getpeername(), None)
                    continue

    #Quitting the thread.
    print "Quitting thread: ", PORT
    queue.put(PORT)
    roomDict.pop(name, None)
    server_socket.close()
    return

# broadcast chat messages to all connected clients
def broadcast (SOCKET_LIST, server_socket, sock, sender, data):
    for socket in SOCKET_LIST:
        # send the message only to peer
        if socket != server_socket and socket != sock :
            try :
                #Server message
                if sender == "server":
                    message = data
                    dh = "server"
                else:
                    message = data
                    dh = sender
                json_string = {"message": message, "dh": dh}
                socket.send(json.dumps(json_string))
            except :
                print "error"
                # broken socket connection
                socket.close()
                # broken socket, remove it
                if socket in SOCKET_LIST:
                    SOCKET_LIST.remove(socket)

def keyExchange(hub_socket, client_socket, server_socket):
    json_string = {"message":"", "dh":"c"}
    client_socket.send(json.dumps(json_string))
    #listen for client keys
    client_public = client_socket.recv(4096)
    #hend the public client key to Hub
    json_string = {"message": client_public, "dh": "h"}
    hub_socket.send(json.dumps(json_string))
    #listen for the encrypted Fernet key from the Hub
    encrypted_fernet = hub_socket.recv(4096)
    #Send the encrypted fernet key, hub pubzlic key and some  encryption data to the client.
    json_string = {"message": encrypted_fernet, "dh": "c1"}
    client_socket.send(json.dumps(json_string))

def createAnVerifySignature(client_socket, addr, user_dictionary):
    #First send the hashed message
    prehash = base64.b64encode(os.urandom(16))
    json_str = {"message":prehash}
    client_socket.send(json.dumps(json_str))
    #Receive signature and public key IMPORTANT!!! Obviously not for production
    unparsed = client_socket.recv(4096)
    data = json.loads(unparsed)
    #Verify the signature and send acknowledgement
    check = verifySignature(data["public_key"], base64.b64decode(data["signature"]), prehash)
    user_dictionary[addr] = data["username"]
    return check

def electNewHub(socket_list, server_socket):
    for socket in SOCKET_LIST:
        if socket != server_socket:
            HUBSOCK = socket
            break
    return HUBSOCK

def initSSL():
    # Initialize context
    #Could be a function from SSLutils.
    ctx = SSL.Context(SSL.TLSv1_2_METHOD)
    ctx.set_options(SSL.OP_NO_SSLv2)
    ctx.set_verify(SSL.VERIFY_PEER|SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_cb)
    ctx.use_privatekey_file (os.path.join('keys', 'server.pkey'))
    ctx.use_certificate_file(os.path.join('', 'server.cert'))
    ctx.load_verify_locations(os.path.join('', 'CA.cert'))
    return ctx

def createServerCert():
    #load CAkey and cert
    file = open('CA.pkey')
    cakey = ''.join(file.readlines())
    cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, cakey)
    file.close()

    file = open('CA.cert')
    cacert = ''.join(file.readlines())
    cacert = crypto.load_certificate(crypto.FILETYPE_PEM, cacert)
    file.close()
    
    #Creating server certificate and signing it with the CA private key. Is ok as the server is also the CA :-) 
    serv_req = createRequest('server')
    serv_cert = signCertificates(serv_req, cacert, cakey)
    #Writes the cert as PEM encoded to disk
    open('server.cert', 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, serv_cert))

def signCertThread():
    print "Started signing thread"
    HOST = ''
    RECV_BUFFER = 4096
    PORT = 9998
    #Creates a dictionary for port and servername
    SOCKET_LIST = []
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    SOCKET_LIST.append(server_socket)

    #load CAkey and cert
    file = open('CA.pkey')
    cakey = ''.join(file.readlines())
    cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, cakey)
    file.close()

    file = open('CA.cert')
    cacert = ''.join(file.readlines())
    cacert = crypto.load_certificate(crypto.FILETYPE_PEM, cacert)
    file.close()

    done = False
    while done == False:

        ready_to_read,ready_to_write,in_error = select.select(SOCKET_LIST,[],[],0)
        for sock in ready_to_read:
            # a new connection request recieved
            if sock == server_socket:
                sockfd, addr = server_socket.accept()

                SOCKET_LIST.append(sockfd)
            else:
                data = sock.recv(4096)
                req = crypto.load_certificate_request(crypto.FILETYPE_ASN1,data)

                #Sign the cert_req with CA and return the certificate.
                cert_to_be_parsed = signCertificates(req, cacert, cakey)
                sock.send(crypto.dump_certificate(crypto.FILETYPE_PEM, cert_to_be_parsed))
                SOCKET_LIST.remove(sock)
                sock.close()


main()
