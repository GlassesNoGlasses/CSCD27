from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer
from http.client import HTTPSConnection
from urllib import parse
import sys

class Server(BaseHTTPRequestHandler):

    def __init__(self, filepath, *args, **kwargs):
            self.filepath = filepath
            super().__init__(*args, **kwargs)

# =============================================
# ========= write your code below  ============
# =============================================

    # GET request handler 
    def do_GET(self):
        # retrieve the path from the HTTP request
        path = self.path
        # retrieve the headers from the HTTP request
        headers = self.headers
        headerKeys = headers.keys()
        newHeaders = {}

        for key in headerKeys:
            newHeaders[key] = headers.get(key)

        url = str(headers.get('host'))
        # retrieve the body from the HTTP request
        
        # send an HTTP request to another server and get the response
        conn = HTTPSConnection(url)
        method = 'GET'
        conn.request(method, path, headers=newHeaders)
        res = conn.getresponse()

        body = res.read().decode()
        
        # set HTTP response status code and body
        self.send_response(res.status)
        # set HTTP reponse headers
        
        for header, value in res.getheaders():
            self.send_header(header, value)

        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

        if (path == '/check'):
            with open(self.filepath, "w") as text_file:
                text_file.write(body)
            conn.close()
            exit(0)
        
        conn.close()

    # POST request handler 
    def do_POST(self):
        #retrieve the path from the HTTP request
        path = self.path
        # retrieve the headers from the HTTP request
        headers = self.headers
        headerKeys = headers.keys()
        newHeaders = {}

        for key in headerKeys:
            newHeaders[key] = headers.get(key)

        url = str(headers.get('host'))
        # retrieve the body from the HTTP request
        body = self.rfile.read(int(self.headers.get('content-length'))).decode()
        
        # send an HTTP request to another server and get the response
        conn = HTTPSConnection(url)
        method = 'POST'
        path = path
        # body = body
        headers = headers
        conn.request(method, path, body=body, headers=newHeaders)
        # and get the response back 
        res = conn.getresponse()
        body = res.read().decode()
        
        # set HTTP response status code and body
        self.send_response(res.status)
        # set HTTP reponse headers
        for header, value in res.getheaders():
            self.send_header(header, value)

        self.end_headers()
        self.wfile.write(body.encode("utf-8"))
        conn.close()
      
    # PUT request handler     
    def do_PUT(self):
         # retrieve the path from the HTTP request
        path = self.path
        # retrieve the headers from the HTTP request
        headers = self.headers
        headerKeys = headers.keys()
        newHeaders = {}

        for key in headerKeys:
            newHeaders[key] = headers.get(key)

        url = str(headers.get('host'))
        # retrieve the body from the HTTP request
        body = self.rfile.read(int(self.headers.get('content-length'))).decode()
        
        # send an HTTP request to another server and get the response
        conn = HTTPSConnection(url)
        method = 'PUT'
        path = path
        conn.request(method, path, body=body, headers=newHeaders)
        res = conn.getresponse()

        body = res.read().decode()
        
        # set HTTP response status code and body
        self.send_response(res.status)
        # set HTTP reponse headers
        
        for header, value in res.getheaders():
            self.send_header(header, value)

        self.end_headers()
        self.wfile.write(body.encode("utf-8"))
        conn.close()

# =============================================
# ===== do not modify the code below ==========
# =============================================
        
def run_server(filepath):
    handler = partial(Server, filepath)
    httpd = HTTPServer(('', 8080), handler)
    httpd.serve_forever()
    
if __name__ == "__main__":
    import os, sys, getopt
    def usage():
       print ('Usage:    ' + os.path.basename(__file__) + ' filepath ')
       sys.exit(2)
    # extract parameters
    try:
         opts, args = getopt.getopt(sys.argv[1:],"h",["help"])
    except getopt.GetoptError as err:
         print(err)
         usage()
         sys.exit(2)
    filepath = args[0] if len(args) > 0 else None
    for opt, arg in opts:
        if opt in ("-h", "--help"):
           usage()
    if (filepath is None):
        print('filepath is missing\n')
        usage()
    # run the command
    run_server(filepath)