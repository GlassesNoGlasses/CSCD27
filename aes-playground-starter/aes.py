#!/usr/local/bin/python3

from PIL import Image
from Crypto.Cipher import AES

# =============================================
# ======= do not change these values ==========
# =============================================

CBC_IV = b'bUQVch74NmLyWACd'
CTR_NONCE = b'PzphkGKm'

# =============================================
# ========= write your code below  ============
# =============================================
        
def encrypt(mode, keyFile, inputFile, outputFile):
    ''' 
    Encrypts the image inputFile with the keyFile using the aes cipher (from PyCryptodome) 
    and writes the image outputFile
    The image outputFile must be a viewable image file.
    (string, string, string, string) -> None
    '''
    key = (open(keyFile, "r").read()).encode()
    inputImage = Image.open(open(inputFile, 'rb'))
    print(inputImage.size)
    content = inputImage.tobytes() + b'neilw'
    print(len(content))
    cipher = None
    cipherText = None

    if (mode == "ecb"):
       cipher = AES.new(key, AES.MODE_ECB)
    elif (mode  == "cbc"):
       cipher = AES.new(key, AES.MODE_CBC, iv=CBC_IV)
    elif (mode == "ctr"):
       cipher = AES.new(key, AES.MODE_CTR, nonce=CTR_NONCE)
   

   #  cipherText = cipher.encrypt(content)
   #  outputImage = Image.frombytes('RGB', inputImage.size, cipherText)
   #  outputImage.save(outputFile)
   #  inputImage.close()
   #  outputImage.close()
    
def decrypt(mode, keyFile, inputFile, outputFile):
    ''' 
    Decrypts the image inputFile with the keyFile using the aes cipher (from PyCryptodome) 
    and writes the image outputFile
    The image outputFile must be a viewable image file.
    (string, string, string, string) -> None
    '''
    key = (open(keyFile, "r").read()).encode()
    inputImage = Image.open(open(inputFile, 'rb'))
    print(inputImage.size)
    content = inputImage.tobytes() + b'neilw'
    print(len(content))
    cipher = None
    plainText = None

    if (mode == "ecb"):
       cipher = AES.new(key, AES.MODE_ECB)
    elif (mode  == "cbc"):
       cipher = AES.new(key, AES.MODE_CBC, iv=CBC_IV)
    elif (mode == "ctr"):
       cipher = AES.new(key, AES.MODE_CTR, nonce=CTR_NONCE)
      
    plainText = cipher.decrypt(content)
    outputImage = Image.frombytes('RGB', inputImage.size, plainText)
    outputImage.save(outputFile)
    inputImage.close()
    outputImage.close()

# =============================================
# ===== do not modify the code below ==========
# =============================================

if __name__ == "__main__":
    import os, sys, getopt
    def usage():
        print ('Usage:    ' + os.path.basename(__file__) + ' options input_file ')
        print ('Options:')
        print ('\t -e, --encrypt')
        print ('\t -d, --decrypt')
        print ('\t -m ecb, --mode=ecb')
        print ('\t -m cbc, --mode=cbc')
        print ('\t -m ctr, --mode=ctr')
        print ('\t -k key_file, --key=key_file')
        print ('\t -o output_file, --output=output_file')
        sys.exit(2)
    try:
      opts, args = getopt.getopt(sys.argv[1:],"hedm:k:o:",["help", "encrypt", "decrypt", "mode=", "key=", "output="])
    except getopt.GetoptError as err:
      print(err)
      usage()
    # extract parameters
    op = None
    mode = None
    keyFile = None
    outputFile = None
    inputFile = args[0] if len(args) > 0 else None
    for opt, arg in opts:
        if opt in ("-h", "--help"):
           usage()
        elif opt in ("-e", "--encrypt"):
           op = encrypt
        elif opt in ("-d", "--decrypt"):
           op = decrypt
        elif opt in ("-m", "--mode"):
           mode = arg
        elif opt in ("-k", "--key"):
           keyFile = arg
        elif opt in ("-n", "--nonce"):
           nonceFile = arg
        elif opt in ("-o", "--output"):
           outputFile = arg
    # check arguments
    if (op is None):
       print('encrypt/decrypt option is missing\n')
       usage()
    if (mode is None):
       print('mode of operation option is missing\n')
       usage()
    if mode not in ["ecb", "cbc", "ctr"]:
        print('mode of operation should be either ecb, cbc or ctr\n')
        usage()
    if (keyFile is None):
       print('key option is missing \n')
       usage()
    if (outputFile is None):
       print('output option is missing\n')
       usage()
    if (inputFile is None):
       print('input_file is missing\n')
       usage()
    # run the command
    op(mode, keyFile, inputFile, outputFile)
