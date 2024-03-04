#!/usr/local/bin/python3

import json
from scapy.all import *

load_layer('http')
load_layer('tls')
load_layer('dns')

results = []

# =============================================
# ========= write your code below  ============
# =============================================
viewedHTTPRequests = []
viewedHTTPSRequests = []
ALICE = "10.0.0.2"


def packet_filter(packet):
    if packet.haslayer('HTTP Request'):
        print("HTTP")
        sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
        if packet[TCP].ack in viewedHTTPRequests or packet[TCP].seq in viewedHTTPRequests:
            if not packet[TCP].ack in viewedHTTPRequests:
                viewedHTTPRequests.append(packet[TCP].ack)
            if not packet[TCP].seq in viewedHTTPRequests:
                viewedHTTPRequests.append(packet[TCP].seq)
            return False
        print("good")
        return (str(sip) == ALICE and packet[TCP].dport == 80)
    if packet.haslayer('TLS Extension - Server Name'):
        print("HTTPS")
        sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
        if packet[TCP].ack in viewedHTTPSRequests or packet[TCP].seq in viewedHTTPSRequests:
            if not packet[TCP].ack in viewedHTTPSRequests:
                viewedHTTPSRequests.append(packet[TCP].ack)
            if not packet[TCP].seq in viewedHTTPSRequests:
                viewedHTTPSRequests.append(packet[TCP].seq)
            return False
        print("good")
        return (str(sip) == ALICE and packet[TCP].dport == 443)
    if packet.haslayer('DNS Question Record') and (packet[UDP].dport == 53):
       print("DNS")
       sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
       qr = packet['DNS Question Record']
       print("good")
       return qr.get_field('qtype').i2repr(qr, qr.qtype) == 'A' and str(sip) == ALICE
    #filter each TCP request
    return False

def packet_process(packet):
    protocol = None
    servername = None
    dport = None

    if packet.haslayer(DNS):
        protocol = "DNS"
        servername = packet[DNS].qd.qname.decode("utf-8")
    elif packet.haslayer(TCP):
        dport = str(packet[TCP].dport)
        ack = str(packet[TCP].ack)
        seq = str(packet[TCP].seq)

        if dport == "80":
            protocol = "HTTP"
            viewedHTTPRequests.append(ack)
            viewedHTTPRequests.append(seq)
            servername = packet['HTTP Request'].Host.decode()
        elif dport == "443":
            protocol = "HTTPS"
            viewedHTTPSRequests.append(ack)
            viewedHTTPSRequests.append(seq)
            servername = packet['TLS Extension - Server Name'].servernames[0].servername.decode() if len(packet['TLS Extension - Server Name'].servernames) > 0 else "unknown"

    # extract the source and destinations IP
    sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
    dip = packet[IPv6].dst if (IPv6 in packet) else packet[IP].dst
    # and the source and destination ports

    # add a record to the output json file
    results.append({"src": sip, "dst": dip, "protocol": protocol, "servername": servername})
    # print a debug message

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