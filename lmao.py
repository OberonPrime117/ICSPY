import dpkt
from socket import inet_ntoa

with open("file2.pcap","rb") as f:
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        ip = dpkt.ethernet.Ethernet(buf).data
        print(inet_ntoa(ip.src), inet_ntoa(ip.dst), ip.len)