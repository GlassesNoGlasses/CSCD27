#!/usr/local/bin/python3

from Crypto.Util.strxor import strxor
import base64
import math

# =============================================
# ========= write your code below  ============
# =============================================

''' cracks the key base on 
    the plaintext (utf-8),
    its corresponding ciphertext (base64 encoded),
    the known key length
    and returns the key (utf-8)
    (string, string, integer) -> string
'''
def crack(plaintext, ciphertext, keyLength):
    encodedPlaintext = plaintext.encode()
    decodedCiphertext = base64.b64decode(ciphertext)

    keyArray = strxor(decodedCiphertext[0:keyLength], encodedPlaintext)
    keyPart = ''.join(chr(i) for i in keyArray)

    realKeyLength = math.ceil(len(decodedCiphertext) / keyLength)
    realKeyRemainderLength = len(decodedCiphertext) % keyLength

    key = (keyPart * realKeyLength)[:len(decodedCiphertext)]

    return key

# =============================================
# ===== do not modify the code below ==========
# =============================================
    
if __name__ == "__main__":
   import os, sys, getopt
   def usage():
        print ('Usage:    ' + os.path.basename(__file__) + ' options key_file')
        print ('Options:')
        print ('\t -c ciphertext_file, --ciphertext=ciphertext_file')
        print ('\t -p plaintext_file, --plaintext=plaintext_file')
        print ('\t -k n, --key-length=n')
        sys.exit(2)
   try:
      opts, args = getopt.getopt(sys.argv[1:],"hc:p:k:",["help", "ciphertext=", "plaintext=", "key-length="])
   except getopt.GetoptError as err:
      print(err)
      usage()
   # extract parameters
   plaintextFile = None
   ciphertextFile = None
   keyLength = None
   keyFile = args[0] if len(args) > 0 else None
   for opt, arg in opts:
        if opt in ("-h", "--help"):
           usage()
        elif opt in ("-c", "--ciphertext"):
           ciphertextFile = arg
        elif opt in ("-p", "--plaintext"):
           plaintextFile = arg
        elif opt in ("-k", "--key-length"):
           keyLength = arg
   # check arguments
   if (plaintextFile is None):
       print('plaintext file option is missing\n')
       usage()
   if (ciphertextFile is None):
       print('ciphertext file option is missing\n')
       usage()
   if (keyLength is None):
       print('key-length option is missing\n')
       usage()
   if (keyFile is None):
       print('key file is missing\n')
       usage()
  # run the command
   with open(ciphertextFile, "r") as ciphertextStream:
        ciphertext = ciphertextStream.read()
        with open(plaintextFile, "r") as plaintextStream:
            plaintext = plaintextStream.read()
            key = crack(plaintext, ciphertext, int(keyLength))
            with open(keyFile, "w") as keyStream:
                keyStream.write(key)