from scapy.all import *

pcap = rdpcap("file2.pcap")

for pkt in pcap:
    if Raw in pkt:
        value = pkt[Raw]
        print(value)