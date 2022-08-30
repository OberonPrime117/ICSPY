# ////////////////// ALL IMPORTS ////////////////////////

from tabulate import tabulate
from OuiLookup import OuiLookup
from scapy.all import *
from scapy.layers.l2 import getmacbyip, Ether
from tkinter import filedialog as fd
import time
from scapy.layers.inet import IP

# ////////////////// PICK THE FILE FUNCTION ////////////////////////

def select_file():
    filetypes = (
        ('PCAP', '*.pcap'),
        ('PCAPNG', '*.pcapng'),
        ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir='/home/artorias/Documents/Github/python-pcap-parser/',
        filetypes=filetypes)

    return filename

# ////////////////// GET PROTOCOL NAME FROM ITS NUMBER ////////////////////////

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rloading ' + str(c))
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\nDone!\t')

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

for packet in packets:
    # ////////////////// INFO GATHER USING SCAPY ////////////////////////
    
    start = time.time()

    length = len(packet)
    for line in packet.show2(dump=True).split('\n'):
        if '###' in line:
            layer = line.strip('#[] ')
            packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            packet_dict[layer][key.strip()] = val.strip()
    
    # ////////////////// RESET VALUES ////////////////////////
    # print("////////////")
    # print(time.time() - start)
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
    # print(time.time() - start)
    start = time.time()

    if 'UDP' in list(packet_dict.keys()):
        data[str(i)]["Source Port"] = packet_dict["UDP"]['sport']
        data[str(i)]["Destination Port"] = packet_dict["UDP"]['dport']
        

    elif 'TCP' in list(packet_dict.keys()):
        data[str(i)]["Source Port"] = packet_dict["TCP"]['sport']
        data[str(i)]["Destination Port"] = packet_dict["TCP"]['dport']

    else:
        data[str(i)]["Source Port"] = "N/A"
        #print(packet.show())
        data[str(i)]["Destination Port"] = "N/A"

    # ////////////////// IP ////////////////////////
    # print("////////////")
    # print(time.time() - start)
    start = time.time()


    try:
        
        if IP in packet:
                data[str(i)]["Source IP"] = str(packet[IP].src) # 0
                data[str(i)]["Destination IP"] = str(packet[IP].dst) # 1
            
        else:
            try:
                data[str(i)]["Source IP"] = packet_dict["802.3"]["src"] # 0
                data[str(i)]["Destination IP"] = packet_dict["802.3"]["dst"] # 1

            except:
                data[str(i)]["Source IP"] = packet[Ether].src # 0
                data[str(i)]["Destination IP"] = packet[Ether].dst # 1

    except:

        try:
            data[str(i)]["Source IP"] = packet_dict["802.3"]["src"] # 0
            data[str(i)]["Destination IP"] = packet_dict["802.3"]["dst"] # 1

        except:
            data[str(i)]["Source IP"] = packet[Ether].src # 0
            data[str(i)]["Destination IP"] = packet[Ether].dst # 1

    # ////////////////// PROTOCOL ////////////////////////
    # print("////////////")
    # print(time.time() - start)
    # start = time.time()
    print(packet.show())
    
    if IP in packet:
        data[str(i)]["Protocol"] = proto_name_by_num(int(packet[IP].proto)) # 2
    else:
        #data[str(i)]["Protocol"] = "Other" # 2
        flag = 0
        y = packet.summary().split()
        for b in y:
            if b.isupper():
                data[str(i)]["Protocol"] = b
                #print(packet.summary())
                flag = 1
                continue
            elif flag == 0: 
                data[str(i)]["Protocol"] = "Other" 
    try :
        for l in protocol:
            if int(data[str(i)]["Source Port"]) in l[1] or int(data[str(i)]["Destination Port"]) in l[1]:
                try:
                    data[str(i)]["Protocol"] = l[0]
                except:
                    data[str(i)]["Protocol"] = l[0]

            
    except:
        pass
    
    if data[str(i)]["Source Port"] in list(protocol.keys()):
        data[str(i)]["Protocol"] = protocol[data[str(i)]["Source Port"]]
        
    if data[str(i)]["Destination Port"] in list(protocol.keys()):
        data[str(i)]["Protocol"] = protocol[data[str(i)]["Destination Port"]]
    
    if str(packet_dict["Ethernet"]["type"]) in list(ethertype.keys()):
        data[str(i)]["Protocol"] = ethertype[str(packet_dict["Ethernet"]["type"])]

    

    # ////////////////// MAC ////////////////////////
    # print("////////////")
    # print(time.time() - start)
    start = time.time()
    
    if str(data[str(i)]["Source IP"]) == "0.0.0.0":
        data[str(i)]["Source MAC"] = "00:21:6a:2d:3b:8e" # 3
        data[str(i)]["Protocol"] = "DHCP"
        
    if str(data[str(i)]["Destination IP"]) == "255.255.255.255":
        data[str(i)]["Destination MAC"] = "ff:ff:ff:ff:ff:ff" # 4
    
    if "::" in str(data[str(i)]["Source IP"]) and "::" in str(data[str(i)]["Destination IP"]):
        data[str(i)]["Source MAC"] =  str(packet[Ether].src) # 3
        data[str(i)]["Destination MAC"] =  str(packet[Ether].dst) # 4

    else:
        try:
            data[str(i)]["Source MAC"] =  packet[Ether].src
        except:
            try:
                data[str(i)]["Source MAC"] = getmacbyip(str(data[str(i)]["Source IP"])) # 3 # 3
            except:
                try:
                    data[str(i)]["Source MAC"] =  packet_dict["802.3"]["src"] # 3
                except:
                    data[str(i)]["Source MAC"] = "" # 3

        try:
            data[str(i)]["Destination MAC"] = packet[Ether].dst # 4
        except:
            try:
                data[str(i)]["Destination MAC"] = getmacbyip(str(data[str(i)]["Destination IP"]))
            except:
                try:
                    data[str(i)]["Destination MAC"] = packet_dict["802.3"]["dst"]
                except:
                    data[str(i)]["Destination MAC"] = ""

    # ////////////////// VENDOR ////////////////////////

    if data[str(i)]["Source MAC"] == 'ff:ff:ff:ff:ff:ff':
        data[str(i)]["Source Vendor"] = "Broadcast"
    else:
        #print(data[str(i)]["Source MAC"])
        try:
            mac_vendor_src = OuiLookup().query(data[str(i)]["Source MAC"])
            data[str(i)]["Source Vendor"] = list(mac_vendor_src[0].items())[0][1]
        except:
            data[str(i)]["Source Vendor"] = ""
    
    if data[str(i)]["Destination MAC"] == 'ff:ff:ff:ff:ff:ff':
        data[str(i)]["Destination Vendor"] = "Broadcast"
    else:
        try:
            mac_vendor_dst = OuiLookup().query(data[str(i)]["Destination MAC"])
            data[str(i)]["Destination Vendor"] = list(mac_vendor_src[0].items())[0][1]
        except:
            data[str(i)]["Destination Vendor"] = ""

    # ////////////////// SRC IP , DST IP ////////////////////////

    #print(time.time() - start)
    start = time.time()

    if (str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"])) in list(ip_new.keys()):
        ip_new[(str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"]))] = ip_new[(str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"]))] + 1
    else:
        ip_new[(str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"]))] = 1
    
    ip_new = dict(sorted(ip_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// PROTOCOL ////////////////////////
    # print("////////////")
    #print(time.time() - start)
    start = time.time()

    if str(data[str(i)]["Protocol"]) in list(proto_new.keys()):
        proto_new[str(data[str(i)]["Protocol"])] = proto_new[str(data[str(i)]["Protocol"])] + 1
    else:
        proto_new[str(data[str(i)]["Protocol"])] = 1
    
    proto_new = dict(sorted(proto_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// SRC IP ////////////////////////
    # print("////////////")
    #print(time.time() - start)
    start = time.time()

    if str(data[str(i)]["Source IP"]) in list(src_new.keys()):
        src_new[str(data[str(i)]["Source IP"])] = src_new[str(data[str(i)]["Source IP"])] + 1
    else:
        src_new[str(data[str(i)]["Source IP"])] = 1
    
    src_new = dict(sorted(src_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// DST IP ////////////////////////
    # print("////////////")
    #print(time.time() - start)
    start = time.time()

    if str(data[str(i)]["Destination IP"]) in list(dst_new.keys()):
        dst_new[str(data[str(i)]["Destination IP"])] = dst_new[str(data[str(i)]["Destination IP"])] + 1
    else:
        dst_new[str(data[str(i)]["Destination IP"])] = 1
    
    dst_new = dict(sorted(dst_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// SRC VENDOR ////////////////////////
    # print("////////////")
    #print(time.time() - start)
    start = time.time()

    if str(data[str(i)]["Source Vendor"]) in list(vendor_new.keys()):
        vendor_new[str(data[str(i)]["Source Vendor"])] = vendor_new[str(data[str(i)]["Source Vendor"])] + 1
    else:
        vendor_new[str(data[str(i)]["Source Vendor"])] = 1
    
    vendor_new = dict(sorted(vendor_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// DST VENDOR ////////////////////////
    # print("////////////")
    #print(time.time() - start)
    start = time.time()

    if str(data[str(i)]["Destination Vendor"]) in list(vendor_new.keys()):
        vendor_new[str(data[str(i)]["Destination Vendor"])] = vendor_new[str(data[str(i)]["Destination Vendor"])] + 1
    else:
        vendor_new[str(data[str(i)]["Destination Vendor"])] = 1
    
    vendor_new = dict(sorted(vendor_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// SRC PORT ////////////////////////
    # print("////////////")
    #print(time.time() - start)
    start = time.time()

    if str(data[str(i)]["Source Port"]) in list(sport_new.keys()):
        sport_new[str(data[str(i)]["Source Port"])] = sport_new[str(data[str(i)]["Source Port"])] + 1
    else:
        sport_new[str(data[str(i)]["Source Port"])] = 1
    
    sport_new = dict(sorted(sport_new.items(),key=lambda item: item[1], reverse=True))

    # ////////////////// DST PORT ////////////////////////
    # print("////////////")
    #print(time.time() - start)
    start = time.time()

    if str(data[str(i)]["Destination Port"]) in list(dport_new.keys()):
        dport_new[str(data[str(i)]["Destination Port"])] = dport_new[str(data[str(i)]["Destination Port"])] + 1
    else:
        dport_new[str(data[str(i)]["Destination Port"])] = 1
    
    dport_new = dict(sorted(dport_new.items(),key=lambda item: item[1], reverse=True))

    i = i + 1

# ////////////////// LIST TO GATHER ALL DATA FOR TABULATE ////////////////////////

i=int(0)
for key in ip_new.keys():
    if i<10:
        newance = []
        newance.append(key[0])
        newance.append(key[1])
        newance.append(ip_new[key])
        transfer2.append(newance)
    else:
        break
    i = i+1

done = True

i=int(0)
for key in dst_new.keys():
    if i<10:
        newance = []
        newance.append(key) 
        newance.append(dst_new[key]) 
        transfer4.append(newance)
    i = i+1

i=int(0)
for key in proto_new.keys():
    newance = []
    newance.append(key) 
    newance.append(proto_new[key]) 
    transfer5.append(newance)
    i = i+1

i=int(0)
for key in sport_new.keys():
    if i<10:
        newance = []
        newance.append(key) 
        newance.append(sport_new[key]) 
        transfer6.append(newance)
    i = i+1

i=int(0)
for key in src_new.keys():
    if i<10:
        newance = []
        newance.append(key) 
        newance.append(src_new[key]) 
        transfer.append(newance)
    i = i+1

i=int(0)
for key in dport_new.keys():
    if i<10:
        newance = []
        newance.append(key)
        newance.append(dport_new[key]) 
        transfer7.append(newance)
    i = i+1

i = int(0)
for key in vendor_new.keys():
    newance = []
    newance.append(key)
    newance.append(vendor_new[key]) 
    transfer3.append(newance)
    i = i+1

# ////////////////// TABULATE ////////////////////////

tabling = tabulate(transfer, headers=["Source","Number of Packets with this Source"])
tabling2 = tabulate(transfer2, headers=["Src IP Address", "Dst IP Address", "Number of Packets Shared"])
tabling3 = tabulate(transfer3, headers=["Vendor Name","Number of Packets with the Vendor"])
tabling4 = tabulate(transfer4, headers=["Destination","Number of Packets with this Destination"])
tabling5 = tabulate(transfer5, headers=["Protocol","Number of Packets with this Protocol"])
tabling6 = tabulate(transfer6, headers=["Source Port","Number of Packets using this Port"])
tabling7 = tabulate(transfer7, headers=["Destination Port","Number of Packets using this Port"])

# ////////////////// FILE WRITING ////////////////////////

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