from scapy.all import Ether, rdpcap, frame
packets = rdpcap('file2.pcap')
for p in packets:
    e = frame[Ether]
    print(e.src,e.dst)