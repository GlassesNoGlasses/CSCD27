#!/usr/local/bin/python3

import json
from scapy.all import *
from urllib.parse import urlparse, parse_qs

load_layer('http')
load_layer('tls')
load_layer('dns')
ALICE = "10.0.0.2"
results = []

# =============================================
# ========= write your code below  ============
# =============================================

def packet_filter(packet):
    if packet.haslayer('HTTP Request'):
        sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
        return (str(sip) == ALICE)
    elif packet.haslayer('HTTP Response'):
        return True
    return False

def packet_process(packet):
    info = {}

    if packet.haslayer('HTTP Request'):
        info["type"] = "request"
        info["host"] = packet['HTTP Request'].Host.decode()
        info["method"] = packet['HTTP Request'].Method.decode()

        path = packet['HTTP Request'].Path.decode()
        info["path"] = path

        if ('?' in path):
            pathArgs = {}
            pathArgsRaw = path[path.find('?') + 1:].split('&') if '&' in path else [path[path.find('?') + 1:]]

            for s in pathArgsRaw:
                pair = s.split('=')
                pathArgs[pair[0]] = pair[1]
            info["query_args"] = pathArgs

        if (packet['HTTP Request'].Cookie and '=' in packet['HTTP Request'].Cookie.decode()):
            cookie = packet['HTTP Request'].Cookie.decode()
            cookieArgs = {}
            cookieArgsRaw = cookie.split(';') if ';' in cookie else [cookie]

            for s in cookieArgsRaw:
                pair = s.strip().split('=')
                cookieArgs[pair[0]] = pair[1]
            info["cookies"] = cookieArgs

        if (packet.haslayer('Raw') and packet['HTTP Request'].Content_Type.decode() == 'application/x-www-form-urlencoded'):
            load = packet['Raw'].load.decode()
            bodyArgs = {}
            bodyArgsRaw = load.split('&') if '&' in load else [load]
            for s in bodyArgsRaw:
                pair = s.split('=')
                bodyArgs[pair[0]] = pair[1]
            info["form"] = bodyArgs
        elif (packet.haslayer('Raw') and packet['Raw'].load):
            info['body'] = packet['Raw'].load.decode()
    
    if packet.haslayer('HTTP Response'):
        info["type"] = "response"
        info["status_code"] = packet['HTTP Response'].Status_Code.decode()

        if (packet['HTTP Response'].Set_Cookie and '=' in packet['HTTP Response'].Set_Cookie.decode()):
            cookie = packet['HTTP Response'].Set_Cookie.decode()
            cookieArgs = {}
            cookieArgsRaw = cookie.split(';') if ';' in cookie else [cookie]
            invalids = ['Max-Age', 'Path', 'Flags', 'Domain']

            for s in cookieArgsRaw:
                pair = s.strip().split('=')
                if (not pair[0] in invalids):
                    cookieArgs[pair[0]] = pair[1]
            info["cookies"] = cookieArgs

        if (packet.haslayer('Raw') and packet['Raw'].load):
            info['body'] = packet['Raw'].load.decode()

    # add a record to the output json file
    results.append(info)


# =============================================
# ===== do not modify the code below ==========
# =============================================

def run(count, filepath):
    sniff(iface="eth0", lfilter=packet_filter, prn=packet_process, count=count)
    with open(filepath, "w") as file_stream:
        file_stream.write(json.dumps(results, indent=4))
    
if __name__ == "__main__":
    import os, sys, getopt
    def usage():
       print ('Usage:	' + os.path.basename(__file__) + ' filepath ')
       print ('\t -c count, --count=count')
       sys.exit(2)
    # extract parameters
    try:
         opts, args = getopt.getopt(sys.argv[1:],"hc:",["help", "count="])
    except getopt.GetoptError as err:
         print(err)
         usage()
         sys.exit(2)
    count = None
    filepath = args[0] if len(args) > 0 else None
    for opt, arg in opts:
        if opt in ("-h", "--help"):
           usage()
        elif opt in ("-c", "--count"):
           try:
                count = int(arg)
           except ValueError:
                print("count must be a natural number")
                sys.exit(2)
    if (count is None):
        print('count option is missing\n')
        usage()
    if (filepath is None):
        print('filepath is missing\n')
        usage()
    # run the command
    run(count, filepath)