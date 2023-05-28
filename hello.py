import pyshark
import json
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, rdpcap, PcapReader
# Path to the pcap file
pcap_file = "S7COMM.pcap"
heights = []
packet_dict = {}
packets = PcapReader(pcap_file)
# Open the pcap file
capture = pyshark.FileCapture(pcap_file)
print(capture[5])