# ////////////////// ALL IMPORTS ////////////////////////

from tabulate import tabulate
from OuiLookup import OuiLookup
from scapy.all import *
from scapy.layers.l2 import getmacbyip, Ether
from tkinter import filedialog as fd
import time
from mac_vendor_lookup import AsyncMacLookup
from scapy.layers.inet import IP
import asyncio
import sys
# ////////////////// PICK THE FILE FUNCTION ////////////////////////

def select_file():
    #filetypes = (
    #    ('PCAP', '*.pcap'),
    #    ('PCAPNG', '*.pcapng'),
    #    ('All files', '*.*')
    #)
    #
    #filename = fd.askopenfilename(
    #    title='Open a file',
    #    initialdir='/home/artorias/Documents/Github/python-pcap-parser/',
    #    filetypes=filetypes)
    print(sys.argv[0])
    print(sys.argv[1])
    filename = sys.argv[1]

    return filename

# ////////////////// GET PROTOCOL NAME FROM ITS NUMBER ////////////////////////

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def find_files(filename, search_path):
    result = []
    for root, dir, files in os.walk(search_path):
        if filename in files:
            result.append(os.path.join(root, filename))
        
    return result

def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rloading ' + str(c))
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\nDone!\t')

async def srcmac(data,packet,packet_dict):
    if str(data[str(i)]["Source IP"]) == "0.0.0.0":
        a = "00:21:6a:2d:3b:8e" # 3

    if "::" in str(data[str(i)]["Source IP"]) and "::" in str(data[str(i)]["Destination IP"]):
        a = str(packet[Ether].src) # 3
    
    else:
        try:
            a = packet[Ether].src
        except:
            try:
                a = getmacbyip(str(data[str(i)]["Source IP"])) # 3 # 3
            except:
                try:
                    a =  packet_dict["802.3"]["src"] # 3
                except:
                    a = "" # 3
    print(a)
    return a
    
async def dstmac(data,packet,packet_dict):
    if str(data[str(i)]["Destination IP"]) == "255.255.255.255":
        a = "ff:ff:ff:ff:ff:ff" # 4
    
    if "::" in str(data[str(i)]["Source IP"]) and "::" in str(data[str(i)]["Destination IP"]):
        a = str(packet[Ether].dst) # 4
    
    else:
        try:
            a = packet[Ether].dst # 4
        except:
            try:
                a = getmacbyip(str(data[str(i)]["Destination IP"]))
            except:
                try:
                    a = packet_dict["802.3"]["dst"]
                except:
                    a = ""
    print(a)
    return a

async def proto(data, packet_dict, packet):
    if IP in packet:
        a = proto_name_by_num(int(packet[IP].proto)) # 2
    else:
        #data[str(i)]["Protocol"] = "Other" # 2
        flag = 0
        y = packet.summary().split()
        for b in y:
            if b.isupper():
                a = b
                flag = 1
                continue
            elif flag == 0: 
                a = "Other" 
    try :
        for l in protocol:
            if int(data[str(i)]["Source Port"]) in l[1] or int(data[str(i)]["Destination Port"]) in l[1]:
                try:
                    a = l[0]
                except:
                    a = l[0]     
    except:
        pass
    
    if str(data[str(i)]["Source Port"]) in list(protocol.keys()):
        a = protocol[str(data[str(i)]["Destination Port"])]
        
    if str(data[str(i)]["Destination Port"]) in list(protocol.keys()):
        a = protocol[str(data[str(i)]["Destination Port"])]

    if "Ethernet" in list(packet_dict.keys()) and str(packet_dict["Ethernet"]["type"]) in list(ethertype.keys()):
        a = ethertype[str(packet_dict["Ethernet"]["type"])]
    
    if str(data[str(i)]["Source IP"]) == "0.0.0.0":
        a = "DHCP"
    
    return a

async def dstvendor(data):
    mac = AsyncMacLookup()
    if data[str(i)]["Destination MAC"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        try:
            #mac_vendor_dst = OuiLookup().query(data[str(i)]["Destination MAC"])
            #mac_vendor_dst = await mac.lookup(str(data[str(i)]["Destination MAC"]))
            #print(mac_vendor_dst,"/////////")
            a = find_files("mac-vendors.json",str(data[str(i)]["Destination MAC"]))
            # list(mac_vendor_dst[0].items())[0][1]
        except:
            a = ""
    print(a)
    return a

async def srcvendor(data):
    mac = AsyncMacLookup()
    if data[str(i)]["Source MAC"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        # print(data[str(i)]["Source MAC"])
        try:
            #mac_vendor_src = OuiLookup().query(data[str(i)]["Source MAC"])
            #mac_vendor_src = await mac.lookup(str(data[str(i)]["Source MAC"]))
            #print(mac_vendor_src,"/////////")
            #a = list(mac_vendor_src[0].items())[0][1]
            a = find_files("mac-vendors.json",str(data[str(i)]["Source MAC"]))
        except:
            a = ""
    
    print(a)
    return a
    
async def srcport(packet_dict):
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['sport']  

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['sport']

    else:
        a = "N/A"
    return a

async def dstport(packet_dict):
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['dport']
        

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['dport']

    else:
        a = "N/A"
    return a

async def srcip(packet, packet_dict):
    try:
        
        if IP in packet:
                a = str(packet[IP].src) # 0
        else:
            try:
                a = packet_dict["802.3"]["src"] # 0
            except:
                a = packet[Ether].src # 0
    except:
        try:
            a = packet_dict["802.3"]["src"] # 0
        except:
            a = packet[Ether].src # 0
    
    return a

async def dstip(packet, packet_dict):
    try:
        if IP in packet:
                a = str(packet[IP].dst) # 1
        else:
            try:
                a = packet_dict["802.3"]["dst"] # 1
            except:
                a = packet[Ether].dst # 1
    except:
        try:
            a = packet_dict["802.3"]["dst"] # 1
        except:
            a = packet[Ether].dst # 1
    return a

async def dash(packet,data,packet_dict):
    start = time.time()
    
    data[str(i)]["Source Port"] = await srcport(packet_dict)
    finish = time.time()
    # print("SRC PORT",finish - start)
    start = time.time()
    data[str(i)]["Destination Port"] = await dstport(packet_dict)
    finish = time.time()
    # print("DST PORT",finish - start)
    start = time.time()
    data[str(i)]["Source IP"] = await srcip(packet, packet_dict)
    finish = time.time()
    # print("SRC IP",finish - start)
    start = time.time()
    data[str(i)]["Destination IP"] = await dstip(packet, packet_dict)
    finish = time.time()
    # print("DST IP",finish - start)
    start = time.time()
    data[str(i)]["Protocol"] = await proto(data, packet_dict, packet)
    finish = time.time()
    # print("PROTOCOL",finish - start)
    start = time.time()
    data[str(i)]["Destination MAC"] = await dstmac(data,packet,packet_dict)
    finish = time.time()
    # print("DST MAC",finish - start)
    start = time.time()
    data[str(i)]["Source MAC"] = await srcmac(data,packet,packet_dict)
    finish = time.time()
    # print("SRC MAC",finish - start)
    start = time.time()
    data[str(i)]["Destination Vendor"] = await dstvendor(data)
    finish = time.time()
    # print("DST VENDOR",finish - start)
    start = time.time()
    data[str(i)]["Source Vendor"] = await srcvendor(data)
    finish = time.time()
    # print("SRC VENDOR",finish - start)
    
    # data[str(i)]["Source Port"],data[str(i)]["Destination Port"],data[str(i)]["Source IP"],data[str(i)]["Destination IP"], data[str(i)]["Protocol"],data[str(i)]["Destination MAC"], data[str(i)]["Source MAC"] , data[str(i)]["Destination Vendor"] , data[str(i)]["Source Vendor"] = await asyncio.gather(srcport(packet_dict), dstport(packet_dict), srcip(packet, packet_dict), dstip(packet, packet_dict), proto(data, packet_dict, packet), dstmac(data,packet,packet_dict), srcmac(data,packet,packet_dict), dstvendor(data), srcvendor(data))
    return data

filep = select_file()
packets = rdpcap(filep)

# ////////////////// VARIABLE DECLARE ////////////////////////

packet_dict = {}
i=1
protocol = {"bacnet" : "BACnet" , "dnp": "DNP3" ,  "mbap" : "Modbus TCP" }
ethertype = {"0x88a4" : "EtherCat", "0x8892" : "PROFINET"}
ip_new = {}
proto_new = {}
vendor_new = {}
dst_new = {}
src_new = {}
sport_new = {}
dport_new = {}
transfer = []
transfer2 = []
transfer3 = []
transfer4 = []
transfer5 = []
transfer6 = []
transfer7 = []
done = False
data = {}


# ////////////////// LOADING ANIMATION ////////////////////////

t = threading.Thread(target=animate)
t.start()
start = time.time()
i = 0
for packet in packets:
    i = i+1
    # print(i)
    # ////////////////// INFO GATHER USING SCAPY ////////////////////////
    length = len(packet)
    for line in packet.show2(dump=True).split('\n'):
        # print(line)
        if '###' in line:
            layer = line.strip('#[] ')
            packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            packet_dict[layer][key.strip()] = val.strip()
    
    # ////////////////// RESET VALUES ////////////////////////
    # print("////////////")
    
    start = time.time()
    
    ip_mac_src_dst = [] 
    route = ""
    data = {}
    data[str(i)] = {}
    data[str(i)]["Frame Number"] = str(i)
    mac_vendor_src = []
    mac_vendor_dst = []

    # ////////////////// PORT ////////////////////////
    # print("////////////")
    # print("RESET time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    data = asyncio.run(dash(packet,data,packet_dict))
    

    

    # ////////////////// IP ////////////////////////
    # print("////////////")
    # print("PORT time taken")
    finish = time.time()
    #print(finish - start)
    start = time.time()
    
    
        
    
    # ////////////////// PROTOCOL ////////////////////////
    # print("////////////")
    # print("IP time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    
    #print(proto_new)

    # ////////////////// MAC ////////////////////////
    # print("////////////")
    # print("PROTOCOL time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    
    

    # ////////////////// VENDOR ////////////////////////
    # print("MAC time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    
    # print(data[str(i)]["Destination Vendor"])
    # print(data[str(i)]["Source Vendor"])

    if str(data[str(i)]["Protocol"]) in list(proto_new.keys()):
        proto_new[str(data[str(i)]["Protocol"])] = proto_new[str(data[str(i)]["Protocol"])] + 1
    else:
        proto_new[str(data[str(i)]["Protocol"])] = 1
    
    proto_new = dict(sorted(proto_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// SRC IP , DST IP ////////////////////////
    # print("VENDOR time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    if (str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"])) in list(ip_new.keys()):
        ip_new[(str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"]))] = ip_new[(str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"]))] + 1
    else:
        ip_new[(str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"]))] = 1
    
    ip_new = dict(sorted(ip_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// SRC IP ////////////////////////
    # print("////////////")
    # print("SRC+DEST time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    if str(data[str(i)]["Source IP"]) in list(src_new.keys()):
        src_new[str(data[str(i)]["Source IP"])] = src_new[str(data[str(i)]["Source IP"])] + 1
    else:
        src_new[str(data[str(i)]["Source IP"])] = 1
    
    src_new = dict(sorted(src_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// DST IP ////////////////////////
    # print("////////////")
    # print("SRC IP time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    if str(data[str(i)]["Destination IP"]) in list(dst_new.keys()):
        dst_new[str(data[str(i)]["Destination IP"])] = dst_new[str(data[str(i)]["Destination IP"])] + 1
    else:
        dst_new[str(data[str(i)]["Destination IP"])] = 1
    
    dst_new = dict(sorted(dst_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// SRC VENDOR ////////////////////////
    # print("////////////")
    # print("DEST IP time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    if str(data[str(i)]["Source Vendor"]) in list(vendor_new.keys()):
        vendor_new[str(data[str(i)]["Source Vendor"])] = vendor_new[str(data[str(i)]["Source Vendor"])] + 1
    else:
        vendor_new[str(data[str(i)]["Source Vendor"])] = 1
    
    vendor_new = dict(sorted(vendor_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// DST VENDOR ////////////////////////
    # print("////////////")
    # print("SRC VENDOR time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    if str(data[str(i)]["Destination Vendor"]) in list(vendor_new.keys()):
        vendor_new[str(data[str(i)]["Destination Vendor"])] = vendor_new[str(data[str(i)]["Destination Vendor"])] + 1
    else:
        vendor_new[str(data[str(i)]["Destination Vendor"])] = 1
    
    vendor_new = dict(sorted(vendor_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// SRC PORT ////////////////////////
    # print("////////////")
    # print("DST VENDOR time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    if str(data[str(i)]["Source Port"]) in list(sport_new.keys()):
        sport_new[str(data[str(i)]["Source Port"])] = sport_new[str(data[str(i)]["Source Port"])] + 1
    else:
        sport_new[str(data[str(i)]["Source Port"])] = 1
    
    sport_new = dict(sorted(sport_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// DST PORT ////////////////////////
    # print("////////////")
    # print("SRC PORT time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()

    if str(data[str(i)]["Destination Port"]) in list(dport_new.keys()):
        dport_new[str(data[str(i)]["Destination Port"])] = dport_new[str(data[str(i)]["Destination Port"])] + 1
    else:
        dport_new[str(data[str(i)]["Destination Port"])] = 1
    # print("DST PORT time taken")
    finish = time.time()
    # print(finish - start)
    start = time.time()
    
    dport_new = dict(sorted(dport_new.items(),key=lambda item: item[1], reverse=True))

    i = i + 1

# ////////////////// LIST TO GATHER ALL DATA FOR TABULATE ////////////////////////
start = time.time()

i=int(0)

for key in ip_new.keys():
    if i<10:
        transfer2.append([key[0],key[1],ip_new[key]])
    else:
        break
    i = i+1

done = True

i = int(0)
for key in vendor_new.keys():
    transfer3.append([key,vendor_new[key]])
    i = i+1

i=int(0)
for key in dst_new.keys():
    if i<10:
        transfer4.append([key,dst_new[key]])
    i = i+1

i=int(0)
for key in proto_new.keys():
    transfer5.append([key,proto_new[key]])
    i = i+1

i=int(0)
for key in sport_new.keys():
    if i<10:
        transfer6.append([key,sport_new[key]])
    i = i+1

i=int(0)
for key in src_new.keys():
    if i<10:
        transfer.append([key,src_new[key]])
    i = i+1

i=int(0)
for key in dport_new.keys():
    if i<10: 
        transfer7.append([key,dport_new[key]])
    i = i+1



# print("NEWANCE time taken")
finish = time.time()
# print(finish - start)

# ////////////////// TABULATE ////////////////////////
start = time.time()
tabling = tabulate(transfer, headers=["Source","Number of Packets with this Source"])
tabling2 = tabulate(transfer2, headers=["Src IP Address", "Dst IP Address", "Number of Packets Shared"])
tabling3 = tabulate(transfer3, headers=["Vendor Name","Number of Packets with the Vendor"])
tabling4 = tabulate(transfer4, headers=["Destination","Number of Packets with this Destination"])
tabling5 = tabulate(transfer5, headers=["Protocol","Number of Packets with this Protocol"])
tabling6 = tabulate(transfer6, headers=["Source Port","Number of Packets using this Port"])
tabling7 = tabulate(transfer7, headers=["Destination Port","Number of Packets using this Port"])
# print("TABULATE time taken")
finish = time.time()
# print(finish - start)

# ////////////////// FILE WRITING ////////////////////////
start = time.time()
with open('report.txt', 'w') as f:
    f.write("Top 10 Pair of IP Addresses which exchange most packets : \n\n")
    f.write(tabling2)

with open('report.txt', 'a') as f:
    f.write("\n\n\nTop 10 Source which communicated the most : \n\n")
    f.write(tabling)

with open('report.txt', 'a') as f:
    f.write("\n\n\nTop 10 Destination which communicated the most : \n\n")
    f.write(tabling4)

with open('report.txt', 'a') as f:
    f.write("\n\n\nVendor Name Derived from Payload : \n\n")
    f.write(tabling3)

with open('report.txt', 'a') as f:
    f.write("\n\n\nPackets using Protocol : \n\n")
    f.write(tabling5)

with open('report.txt', 'a') as f:
    f.write("\n\n\nPackets using Particular Source Port : \n\n")
    f.write(tabling6)

with open('report.txt', 'a') as f:
    f.write("\n\n\nPackets using Particular Destination Port : \n\n")
    f.write(tabling7)

# print("TABLING time taken")
finish = time.time()
# print(finish - start)