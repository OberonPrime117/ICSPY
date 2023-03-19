from scapy.all import PcapReader

packet_dict = {}
for packet in PcapReader("pcap/OG/fuzz.pcap"):
    packet_dict = {}
    heights = []
    for line in packet.show2(dump=True).split('\n'):
        if '###' in line:
            layer = line.strip('#[] ')
            heights.append(layer)
            packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            packet_dict[layer][key.strip()] = val.strip()
    #print(packet_dict)
    print(heights)