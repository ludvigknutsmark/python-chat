import sys, socket, select, os
from mk_cert_files import *
from OpenSSL import SSL


def getCertificate():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    #connect to server
    try:
        s.connect(('localhost', 9998))
    except :
        print "Unable to connect. Either the server is down or the certificate can not be verified."
        sys.exit()

    #This is really important that this is the first thing happening BEFORE any other exchange
    #Create certificate request
    req = createRequest('client')
    s.send(crypto.dump_certificate_request(crypto.FILETYPE_ASN1, req))

    cert_to_be_parsed = s.recv(4096)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_to_be_parsed)
    open('client.cert', 'w').write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    

def initSSLClient(port):
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.set_verify(SSL.VERIFY_PEER, verify_cb)
    ctx.use_privatekey_file (os.path.join('keys', 'client.pkey'))
    ctx.use_certificate_file(os.path.join('', 'client.cert'))
    ctx.load_verify_locations(os.path.join('', 'CA.cert'))
    #Connect the SSL sock
    s = SSL.Connection(ctx, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    s.connect(('localhost', port))
    return s

#Don't actually know how to do this callback, so for a production update this needs to be updated...
def verify_cb(conn, cert, errnum, depth, ok):
    return ok