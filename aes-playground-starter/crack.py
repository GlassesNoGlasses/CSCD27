#!/usr/local/bin/python3

from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from PIL import Image

# =============================================
# ========= write your code below  ============
# =============================================

def crack(imgFile1, imgFile2, outputFile):
    ''' Takes two images imgFile1 and imgFile2 encrypted in AES-CTR with the same key and the same nonce
        and create a new file that leaks some information about the two plaintext inputs
        (string, string, string) -> None
    '''
    inputImage1 = Image.open(open(imgFile1, 'rb'))
    inputImage2 = Image.open(open(imgFile2, 'rb'))
    content1 = inputImage1.tobytes()
    content2 = inputImage2.tobytes()
    
    sameBits = strxor(content1, content2)

    outputImage = Image.frombytes('RGB', inputImage1.size, sameBits)
    outputImage.save(outputFile)
    inputImage1.close()
    inputImage2.close()
    outputImage.close()

# =============================================
# ===== do not modify the code below ==========
# =============================================
    
if __name__ == "__main__":
    import os, sys, getopt
    def usage():
        print ('Usage:    ' + os.path.basename(__file__) + ' options image_1 image_2 ')
        print ('Options:')
        print ('\t -o output_file, --output=output_file [default=output.ppm]')
        sys.exit(2)
    try:
      opts, args = getopt.getopt(sys.argv[1:],"hedk:o:",["help", "output="])
    except getopt.GetoptError as err:
      print(err)
      usage()
    # extract parameters
    outputFile = None
    for opt, arg in opts:
         if opt in ("-h", "--help"):
            usage()
         elif opt in ("-o", "--output"):
            outputFile = arg
    if (outputFile is None):
        print('output option is missing\n')
        usage()
    if len(args) == 2:
        imgFile1 = args[0]
        imgFile2 = args[1]
    else:
        usage()
    crack(imgFile1, imgFile2, outputFile)

