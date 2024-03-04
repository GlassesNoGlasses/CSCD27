#!/usr/local/bin/python3

import sys
from urllib.parse import urlparse, parse_qs, quote
import http.client
import hlextend

# =============================================
# ========= write your code below  ============
# =============================================

def attack(url):
    newUrl = url
    # parameter url is the attack url you construct
    parsed1 = urlparse(url)
    
    # open a connection to the server
    httpconn = http.client.HTTPSConnection(parsed1.hostname, parsed1.port)

    # issue server-API request
    httpconn.request("GET", parsed1.path + "?" + parsed1.query)

    # httpresp is response object containing a status value and possible message
    httpresp = httpconn.getresponse()

    params = parse_qs(parsed1.query)

    if (not params) or (not params['tag']) or (not params['sid']):
        return None

    tag = params['tag'][0]
    sid = params['sid'][0]
    sidQuery = "sid=" + sid

    extension = b'&' + sidQuery.encode() + b'&mark=100'
    sha2 = hlextend.new('sha256')
    sha2.extend(tag.encode(), extension)

    newTag = sha2.hexdigest()
    tagQuery = "tag=" + newTag

    for i in range(8, 21):
       trial = "&" + sidQuery + quote(sha2.padding(len(sidQuery)+ i)) + extension.decode()
       trialUrl = parsed1.scheme + "://" + parsed1.netloc + parsed1.path + "?" + tagQuery + trial

       parsed = urlparse(trialUrl)

       httpconn = http.client.HTTPSConnection(parsed.hostname, parsed.port)
       httpconn.request("GET", parsed.path + "?" + parsed.query)
       httpresp = httpconn.getresponse()

       if httpresp.status == 200:
           newUrl = trialUrl
           break

    # return the url that made the attack successul 
    return newUrl

# =============================================
# ===== do not modify the code below ==========
# =============================================
            
if __name__ == "__main__":
   import os, sys, getopt
   def usage():
        print ('Usage:    ' + os.path.basename(__file__) + ' url ')
        sys.exit(2)
   try:
      opts, args = getopt.getopt(sys.argv[1:],"h",["help"])
   except getopt.GetoptError as err:
      print(err)
      usage()
   # extract parameters
   url = args[0] if len(args) > 0 else None
   # check arguments
   if (url is None):
       print('url is missing\n')
       usage()
   # run the command
   print(attack(url))