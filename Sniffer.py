from scapy.all import sniff, TCP

def packet_handler(packet):
    if packet.haslayer(TCP) and len(packet) > 1000:
        print(packet.summary())

sniff(filter="tcp port 9999", prn=packet_handler, store=0)