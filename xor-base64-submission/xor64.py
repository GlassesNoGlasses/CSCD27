#!/usr/local/bin/python3

from Crypto.Util.strxor import strxor
import base64

# =============================================
# ========= write your code below  ============
# =============================================

''' encrypts the plaintext (utf-8) with a key
    based on the xor cipher algorithm
    and returns the ciphertext (base64 encoded)
    (string, string) -> string
'''
def encrypt(key, plaintext):
    if (len(key) != len(plaintext)):
        print("Error: key and plaintext not same size.", file=sys.stderr)
    
    encoded = plaintext.encode('UTF-8')
    encodedKey = key.encode('UTF-8')

    xor = strxor(encoded, encodedKey)
    b64 = base64.b64encode(xor)

    ciphertext = ''.join(chr(i) for i in b64)

    return ciphertext

''' decrypts the ciphertext (base64 encoded) with a key
    based on the xor cipher algorithm
    and returns the plaintext (utf-8)
    (string, string) -> string
'''    
def decrypt(key, ciphertext):
    decoded = base64.b64decode(ciphertext)
    decodedKey = key.encode()

    if (len(decoded) != len(decodedKey)):
        print("Error: key and ciphertext not same size.", file=sys.stderr)

    xor = strxor(decoded, decodedKey)
    plaintext = ''.join(chr(i) for i in xor)

    return plaintext

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
        print ('\t -k key_file, --key=key_file')
        print ('\t -o output_file, --output=output_file')
        sys.exit(2)
   try:
      opts, args = getopt.getopt(sys.argv[1:],"hedk:o:",["help", "encrypt", "decrypt", "key=", "output="])
   except getopt.GetoptError as err:
      print(err)
      usage()
   # extract parameters
   mode = None
   keyFile = None
   outputFile = None
   inputFile = args[0] if len(args) > 0 else None
   for opt, arg in opts:
        if opt in ("-h", "--help"):
           usage()
        elif opt in ("-e", "--encrypt"):
           mode = encrypt
        elif opt in ("-d", "--decrypt"):
           mode = decrypt
        elif opt in ("-k", "--key"):
           keyFile = arg
        elif opt in ("-o", "--output"):
           outputFile = arg
   # check arguments
   if (mode is None):
       print('encrypt/decrypt option is missing\n')
       usage()
   if (keyFile is None):
       print('key option is missing\n')
       usage()
   if (outputFile is None):
       print('output option is missing\n')
       usage()
   if (inputFile is None):
       print('input_file is missing\n')
       usage()
  # run the command
   with open(keyFile, "r") as keyStream:
        key = keyStream.read()
        with open(inputFile, "r") as inputStream:
            data = inputStream.read()
            output = mode(key, data)
            with open(outputFile, "w") as outputStream:
                outputStream.write(output)
