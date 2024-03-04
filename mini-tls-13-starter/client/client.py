BUFFER_SIZE = 1048576  # the file size is limited to 1 mb
DH_G = 5               # co-prime
DH_KEY_SIZE = 256      # bytes
DH_NONCE_SIZE = 16     # bytes
AES_KEY_SIZE = 32      # bytes

import os, socket, json

from Crypto.Util import number
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from OpenSSL import crypto

# =============================================
# ========= write your code below  ============
# =============================================

def verify_certificate_chain(certificate, config):
    trusted_certs = config['roots']

    #Create a certificate store and add your trusted certs
    try:
        store = crypto.X509Store()

        # Assuming the certificates are in PEM format in a trusted_certs list
        for _cert in trusted_certs:
            client_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, _cert.encode())
            store.add_cert(client_certificate)

        # Create a certificate context using the store and the downloaded certificate
        store_ctx = crypto.X509StoreContext(store, certificate)

        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()

        return True

    except Exception as e:
        return False


# the argument config contains all information passed to the command line
# you should explore what stores in it
# and use it to store anything you need between the different handlers
def send_client_hello(sock, config):
    # create and send client_hello payload
    nonce = get_random_bytes(DH_NONCE_SIZE)
    p = number.getStrongPrime(2048, DH_G)
    a = number.getRandomNBitInteger(2048)
    dhA = pow(DH_G, a, p)

    payload = p.to_bytes(256, byteorder='big') + dhA.to_bytes(256, byteorder='big') + nonce

    sock.sendall(payload)
     # update config
    config['nonce'] = nonce
    config['p'] = p
    config['a'] = a
    config['dhA'] = dhA

def receive_server_hello(sock, config):
    # receive and decode server_hello payload
    payload = sock.recv(BUFFER_SIZE)
    dhB = payload[:256]
    n1 = payload[256:DH_NONCE_SIZE + 256]
    aes_nonce = payload[DH_NONCE_SIZE + 256: 256 + 2*DH_NONCE_SIZE]
    mac = payload[256 + 2*DH_NONCE_SIZE: 256 + 3*DH_NONCE_SIZE]
    e_message = payload[256 + 3*DH_NONCE_SIZE:]


    m = pow(int.from_bytes(dhB, byteorder='big'), config['a'], config['p'])

    k = HKDF(m.to_bytes(DH_KEY_SIZE, byteorder='big'), AES_KEY_SIZE, config['nonce'] + n1, SHA256, 1)

    cipher = AES.new(k, AES.MODE_GCM, nonce=aes_nonce)
    plaintext = cipher.decrypt_and_verify(e_message, mac)
    certificate = crypto.load_certificate(type=crypto.FILETYPE_PEM, buffer=plaintext[512:])
    subject = certificate.get_subject()

    if (subject.O != config['to'] or not verify_certificate_chain(certificate, config)):
        sys.exit(1)

    pubKey = certificate.get_pubkey()
    rsaKey = RSA.import_key(crypto.dump_publickey(crypto.FILETYPE_PEM, pubKey))
    hash = SHA256.new(config['nonce'] + n1 + config['dhA'].to_bytes(256, byteorder='big') + dhB + plaintext[512:])

    try:
        pkcs1_15.new(rsaKey).verify(hash, plaintext[:512])
    except(ValueError, TypeError):
        sys.exit(1)

    config['sessionKey'] = k


def send_request(sock, config):
    # create and send request payload
    plaintext = json.dumps({'request': config['request'], 'filename': config['filename'], 'from': config['from']})
    cipher = AES.new(config['sessionKey'], AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

    payload = nonce + tag + ciphertext

    sock.sendall(payload)

def receive_ready(sock, config):
    # receive data from client
    data = sock.recv(BUFFER_SIZE)
    nonce = data[:16]
    mac = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(config['sessionKey'], AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, mac)

    payload = plaintext.decode('utf-8')
    metada = json.loads(payload)
    # check if server is ready
    if not metada['ready']:
        sys.exit(1)

def send_upload(sock, config):
    # check if file exists
    if not os.path.exists(config['filepath']):
        sys.exit(1)
    # read the file content
    file_out = open(config['filepath'], "rb")
    file_content = file_out.read()
    file_out.close()

    cipher = AES.new(config['sessionKey'], AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(file_content)

    payload = nonce + tag + ciphertext
    # send file content to server
    sock.sendall(payload)

def receive_download(sock, config):
    # receive data from the server
    data = sock.recv(BUFFER_SIZE)
    nonce = data[:16]
    tag = data[16:32]
    cipherText = data[32:]
    cipher = AES.new(config['sessionKey'], AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(cipherText, tag)

    # extract file_content
    file_content = plaintext
    # check if filepath exists
    dirname = os.path.dirname(config['filepath'])
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    # and save the file  locally
    file_out = open(config['filepath'], "wb")
    file_out.write(file_content)
    file_out.close()

# =============================================
# ===== do not modify the code below ==========
# =============================================

def client(config):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # handshake
        sock.connect((host, port))
        send_client_hello(sock, config)
        receive_server_hello(sock, config)
        # data exchange
        send_request(sock, config)
        if config['request'] == 'upload':
            receive_ready(sock, config)
            send_upload(sock, config)
        elif config['request'] == 'download':
            receive_download(sock, config)
    
if __name__ == "__main__":
    import os, sys, getopt
    def usage():
        print ('Usage:    ' + os.path.basename(__file__) + ' options filepath ')
        print ('Options:')
        print ('\t -f from, --from=from')
        print ('\t -t to, --to=to')
        print ('\t -r roots, --roots=roots')
        print ('\t -u, --upload')
        print ('\t -d, --download')
        print ('\t -f filename, --filename=filename')
        sys.exit(2)
    try:
      opts, args = getopt.getopt(sys.argv[1:],"hudp:s:f:t:r:f:",["help", "upload", "download", "from=", "to=", "roots=", "filename="])
    except getopt.GetoptError as err:
      print(err)
      usage()
    # extract parameters
    request = None
    fr = None
    to = None
    roots = None
    filename = None
    filepath = args[0] if len(args) > 0 else None
    for opt, arg in opts:
        if opt in ("-h", "--help"):
           usage()
        elif opt in ("-u", "--upload"):
           request = 'upload'
        elif opt in ("-d", "--download"):
           request = 'download'
        elif opt in ("-f", "--from"):
           fr = arg
        elif opt in ("-t", "--to"):
           to = arg
        elif opt in ("-r", "--roots"):
           roots = arg
        elif opt in ("-f", "--filename"):
           filename = arg
    # check arguments
    if (request is None):
       print('upload/download option is missing\n')
       usage()
    if (fr is None):
       print('from option is missing\n')
       usage()
    if (to is None):
       print('to option is missing\n')
       usage()
    if (roots is None):
       print('roots option is missing\n')
       usage()      
    if (filename is None):
       print('filename option is missing\n')
       usage()
    if (filepath is None):
       print('filepath is missing\n')
       usage()
    # create config
    config = {'request': request, 'from': fr, 'filename': filename, 'filepath': filepath}
    # extract server information
    config['to'] = to.split("@")[0]
    host = to.split("@")[1].split(":")[0]
    port = int(to.split(":")[1])
    # extract all root certificates
    if not os.path.exists(roots):
        print('root certificates path does not exists\n')
        usage()
    else:
        list_of_files = os.listdir(roots)
        config['roots']=[]
        for file in list_of_files:
            f = open(os.path.join(roots, file), "r")
            config['roots'].append(f.read())
            f.close()
    # run the client
    client(config)
        

