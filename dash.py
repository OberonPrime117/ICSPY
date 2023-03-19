from components import srcport, dstport, srcip, dstip, dstmac, srcmac, dstvendor, srcvendor, proto

def dash(packet,data,packet_dict,i,es):
    
    #start = time.process_time()
    data["Source Port"] = srcport(packet_dict)
    #print(time.process_time() - start)

    #start = time.process_time()
    data["Destination Port"] = dstport(packet_dict)
    #print(time.process_time() - start)

    #start = time.process_time()
    data["Source IP"] = srcip(packet, packet_dict)
    #print(time.process_time() - start)

    #start = time.process_time()
    data["Destination IP"] = dstip(packet, packet_dict)
    #print(time.process_time() - start)

    #start = time.process_time()
    data["Destination MAC"] = dstmac(data,packet,packet_dict,i)
    #print(time.process_time() - start)

    #start = time.process_time()
    data["Source MAC"] = srcmac(data,packet,packet_dict,i)
    #print(time.process_time() - start)

    #start = time.process_time()
    data["Destination Vendor"] = dstvendor(data,es)
    #print(time.process_time() - start)

    #start = time.process_time()
    data["Source Vendor"] = srcvendor(data,es)
    #print(time.process_time() - start)

    #start = time.process_time()
    data["Protocol"] = proto(data, packet_dict, packet,i)
    #print(time.process_time() - start)

    return data