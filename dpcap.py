import dpkt
import datetime
from dp import *
f = open('pcap/OG/file2.pcap','rb')
pcap = dpkt.pcap.Reader(f)
for timestamp,buf in pcap:
    # Print out the timestamp in UTC
    print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

    # Unpack the Ethernet frame (mac src/dst, ethertype)
    eth = dpkt.ethernet.Ethernet(buf)
    print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

    # Make sure the Ethernet frame contains an IP packet
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        continue

    # Now unpack the data within the Ethernet frame (the IP packet)
    # Pulling out src, dst, length, fragment info, TTL, and Protocol
    ip = eth.data
    #print(ip.dport)
    #print(ip.sport)

    proto = ip.get_proto(ip.p).__name__
    print(proto)

    # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
    do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
    more_fragments = bool(ip.off & dpkt.ip.IP_MF)
    fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

    # Print out the info
    print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
          (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))

