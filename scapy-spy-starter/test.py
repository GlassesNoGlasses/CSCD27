from scapy.all import *

# def packet_filter(packet):
#     return packet.haslayer(TCP)

# def packet_process(packet):
#     sip = packet[IPv6].src if (IPv6 in packet) else packet[IP].src
#     dip = packet[IPv6].dst if (IPv6 in packet) else packet[IP].dst
#     sport = str(packet[TCP].sport)
#     dport = str(packet[TCP].dport)
#     print("from " + sip + ":" + sport + " to " + dip + ":" + dport)

# def packet_filter(packet):
#    if packet.haslayer('DNS Question Record') and (packet[UDP].dport == 53):
#        qr = packet['DNS Question Record']
#        return qr.get_field('qtype').i2repr(qr, qr.qtype) == 'A' 
#    return False

# def packet_process(packet):
#     print(packet[DNS].qd.qname.decode("utf-8"))

# sniff(iface="eth0",  lfilter=packet_filter, prn=packet_process, count=20)


def packet_process(packet):
    packet.show()

sniff(iface="eth0", prn=packet_process, count=20)
