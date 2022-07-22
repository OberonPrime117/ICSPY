from scapy.all import *
from scapy.layers.inet import IP,ICMP,UDP,TCP
packets = rdpcap("Ultima.pcapng")

for packet in packets:
    if IP in packet and TCP in packet:
        print(packet[TCP].payload)