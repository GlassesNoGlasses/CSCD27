#!/usr/local/bin/python3

from Crypto.Cipher import ChaCha20
import wave
import math

# =============================================
# ========= write your code below  ============
# =============================================

def encrypt(keyFile, inputFile, outputFile):
    ''' 
    Encrypts the wave inputFile with the keyFile using the ChaCha20 cipher (from PyCryptodome)
    and writes the wave outputFile
    The wave outputFile must be a playable wave file.
    (string, string, string) -> None
    '''

    if inputFile.find('.wav') == -1 or outputFile.find('.wav') == -1:
       return None

    keyString = open(keyFile, "r").read()
    key = None

    if (len(keyString) > 32):
       key = keyString[:32].encode()
    elif (len(keyString) < 32):
       remainder = math.ceil((32 - len(keyString)))
       key = (keyString * remainder)[:32].encode()
    else:
       key = keyString.encode()

    cipher = ChaCha20.new(key=key)
    input = wave.open(inputFile, "rb")
    frames = input.getnframes()
    params = input.getparams()
    plaintext = input.readframes(frames)
    output = wave.open(outputFile, "wb")

    ciphertext = cipher.nonce + cipher.encrypt(plaintext)

    output.setnframes(frames)
    output.setparams(params)
    output.writeframes(ciphertext)

    input.close()
    output.close()
    return None
    
def decrypt(keyFile, inputFile, outputFile):
    ''' 
    Decrypts the wave inputFile with the keyFile using the ChaCha20 cipher (from PyCryptodome)
    and writes the wave wave outputFile
    The wave output file must be a playable wave file. 
    (string, string, string) -> None
    '''

    if inputFile.find('.wav') == -1 or outputFile.find('.wav') == -1:
       return None

    keyString = open(keyFile, "r").read()
    key = None

    if (len(keyString) > 32):
       key = keyString[:32].encode()
    elif (len(keyString) < 32):
       remainder = math.ceil((32 - len(keyString)))
       key = (keyString * remainder)[:32].encode()
    else:
       key = keyString.encode()
      
    input = wave.open(inputFile, "rb")
    frames = input.getnframes()
    params = input.getparams()
    encryptedFile = input.readframes(frames)
    output = wave.open(outputFile, "wb")

    msg_nonce = encryptedFile[:8]
    ciphertext = encryptedFile[8:]
    cipher = ChaCha20.new(key=key, nonce=msg_nonce)
    plaintext = cipher.decrypt(ciphertext)

    output.setnframes(frames)
    output.setparams(params)
    output.writeframes(plaintext)

    input.close()
    output.close()
    return None

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
    mode(keyFile, inputFile, outputFile)
