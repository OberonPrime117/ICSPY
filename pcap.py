from ast import excepthandler
import json
import requests
from tabulate import tabulate
from OuiLookup import OuiLookup
from scapy.all import *
from scapy.layers.l2 import getmacbyip, Ether
from tkinter import filedialog as fd
import json
from mac_vendor_lookup import MacLookup
import time
from scapy.layers.inet import IP,ICMP,UDP,TCP
def select_file():
    filetypes = (
        ('PCAP', '*.pcap'),
        ('PCAPNG', '*.pcapng'),
        ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir='/',
        filetypes=filetypes)

    return filename

def get_mac_details(mac_address):
    url = "https://api.macvendors.com/"
    response = requests.get(url+mac_address)
    if response.status_code != 200:
        raise Exception("[!] Invalid MAC Address!")
    return response.content.decode()

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"


filep = select_file()
packets = rdpcap(filep)

i=1


packet_dict = {}
protocol = {"BACnet":[47808], "DNP3": [20000,20000], "EtherCAT": [34980], "Ethernet/IP" : [44818,2222,44818],
            "FL-net" : [55000 , 55001 ,55002 ,55003 ] , "Foundation Fieldbus HSE": [1089 ,1090 ,1091, 1089  ], "ICCP":[102], "Modbus TCP":[502],
            "OPC UA Discovery Server" : [4840], "OPC UA XML": [80,443], "PROFINET": [34962 ,34963 ,34964],"ROC Plus" : [4000]}

#keys_to_remove = {"802.3"}
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
with open('data.json', 'w') as f:
    json.dump("", f)
data = {}

done = False

def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rloading ' + str(c))
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\nDone!\t')

t = threading.Thread(target=animate)
t.start()


for packet in packets:
    #print(str(i))
    # /////////////////////////////////////////////////////////////////////////////////
    # ADDITIONAL INFORMATION INSIDE DATA.JSON 

    length = len(packet)
    for line in packet.show2(dump=True).split('\n'):
        if '###' in line:
            layer = line.strip('#[] ')
            packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            packet_dict[layer][key.strip()] = val.strip()
    
    


    # /////////////////////////////////////////////////////////////////////////////////
    # RESET VALUES 
    
    #start = time.process_time()
    
    ip_mac_src_dst = [] # SOURCE IP , DST IP , PROTOCOL , MAC SRC , MAC DST
    route = ""
    data = {}
    data[str(i)] = {}
    data[str(i)]["Frame Number"] = str(i)
    mac_vendor_src = []
    mac_vendor_dst = []

    #print(time.process_time() - start)

    # /////////////////////////////////////////////////////////////////////////////////
    # SRC & DST IP ADDRESS & PROTOCOL 
    #start = time.process_time()

    if 'UDP' in list(packet_dict.keys()):
        data[str(i)]["Source Port"] = packet_dict["UDP"]['sport']
        data[str(i)]["Destination Port"] = packet_dict["UDP"]['dport']
    elif 'TCP' in list(packet_dict.keys()):
        data[str(i)]["Source Port"] = packet_dict["TCP"]['sport']
        data[str(i)]["Destination Port"] = packet_dict["TCP"]['dport']
        #print(packet_dict["TCP"]['dport'])

    else:
        data[str(i)]["Source Port"] = "N/A"
        data[str(i)]["Destination Port"] = "N/A"
        #print(list(packet_dict.keys()))


    try:
        data[str(i)]["Source IP"] = packet[Ether].src # 0
        data[str(i)]["Destination IP"] = packet[Ether].dst # 1
    except:
        try:
            data[str(i)]["Source IP"] = packet_dict["802.3"]["src"] # 0
            data[str(i)]["Destination IP"] = packet_dict["802.3"]["dst"] # 1
        except:
            if IP in packet:
                data[str(i)]["Source IP"] = str(packet[IP].src) # 0
                data[str(i)]["Destination IP"] = str(packet[IP].dst) # 1

    # ////////////////// PROTOCOL ////////////////////////
    
    if IP in packet:
        data[str(i)]["Protocol"] = proto_name_by_num(int(packet[IP].proto)) # 2
    else:
        data[str(i)]["Protocol"] = "Other" # 2

    print(list(protocol.items()))
    for key,l in list(protocol.items()):
        print(key)
        print(l)
        if data[str(i)]["Source Port"] in l or data[str(i)]["Destination Port"] in l:
            print(key)
            try:
                data[str(i)]["Protocol"] = key
                print(key)
            except:
                data[str(i)]["Protocol"] = key
                print(key)

    # ////////////////// MAC ////////////////////////

    if str(data[str(i)]["Source IP"]) == "0.0.0.0":
        data[str(i)]["Source MAC"] = "00:21:6a:2d:3b:8e" # 3
    
    if str(data[str(i)]["Destination IP"]) == "255.255.255.255":
        data[str(i)]["Destination MAC"] = "ff:ff:ff:ff:ff:ff" # 4
    
    if "::" in str(data[str(i)]["Source IP"]) and "::" in str(data[str(i)]["Destination IP"]):
        data[str(i)]["Source MAC"] =  str(packet[Ether].src) # 3
        data[str(i)]["Destination MAC"] =  str(packet[Ether].dst) # 4

    else:
        try:
            data[str(i)]["Source MAC"] = getmacbyip(str(data[str(i)]["Source IP"])) # 3
        except:
            try:
                data[str(i)]["Source MAC"] =  packet[Ether].src # 3
            except:
                try:
                    data[str(i)]["Source MAC"] =  packet_dict["802.3"]["src"] # 3
                except:
                    data[str(i)]["Source MAC"] = "" # 3

        try:
            data[str(i)]["Destination MAC"] = getmacbyip(str(data[str(i)]["Destination IP"])) # 4
        except:
            try:
                data[str(i)]["Destination MAC"] = packet[Ether].dst # 4
            except:
                try:
                    data[str(i)]["Destination MAC"] = packet_dict["802.3"]["dst"] # 4
                except:
                    data[str(i)]["Destination MAC"] = "" # 4

    # ////////////////// VENDOR ////////////////////////
    if data[str(i)]["Source MAC"] == 'ff:ff:ff:ff:ff:ff':
        data[str(i)]["Source Vendor"] = "Broadcast"
    else:
        mac_vendor_src = OuiLookup().query(data[str(i)]["Source MAC"])
        data[str(i)]["Source Vendor"] = list(mac_vendor_src[0].items())[0][1] # temp 6

    if data[str(i)]["Destination MAC"] == 'ff:ff:ff:ff:ff:ff':
        data[str(i)]["Destination Vendor"] = "Broadcast"
    else:
        mac_vendor_dst = OuiLookup().query(data[str(i)]["Destination MAC"])
        data[str(i)]["Destination Vendor"] = list(mac_vendor_src[0].items())[0][1]
    
    # ////////////////// _NEW LIST FOR TABULATE DATA ////////////////////////

    if (str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"])) in list(ip_new.keys()):
        ip_new[(str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"]))] = ip_new[(str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"]))] + 1
    else:
        ip_new[(str(data[str(i)]["Source IP"]), str(data[str(i)]["Destination IP"]))] = 1
    
    ip_new = dict(sorted(ip_new.items(),key=lambda item: item[1], reverse=True))

    if str(data[str(i)]["Protocol"]) in list(proto_new.keys()):
        proto_new[str(data[str(i)]["Protocol"])] = proto_new[str(data[str(i)]["Protocol"])] + 1
    else:
        proto_new[str(data[str(i)]["Protocol"])] = 1
    
    proto_new = dict(sorted(proto_new.items(),key=lambda item: item[1], reverse=True))
    
    # /////////////

    if str(data[str(i)]["Source IP"]) in list(src_new.keys()):
        src_new[str(data[str(i)]["Source IP"])] = src_new[str(data[str(i)]["Source IP"])] + 1
    else:
        src_new[str(data[str(i)]["Source IP"])] = 1
    
    src_new = dict(sorted(src_new.items(),key=lambda item: item[1], reverse=True))

    if str(data[str(i)]["Destination IP"]) in list(dst_new.keys()):
        dst_new[str(data[str(i)]["Destination IP"])] = dst_new[str(data[str(i)]["Destination IP"])] + 1
    else:
        dst_new[str(data[str(i)]["Destination IP"])] = 1
    
    dst_new = dict(sorted(dst_new.items(),key=lambda item: item[1], reverse=True))


    if str(data[str(i)]["Source Vendor"]) in list(vendor_new.keys()):
        vendor_new[str(data[str(i)]["Source Vendor"])] = vendor_new[str(data[str(i)]["Source Vendor"])] + 1
    else:
        vendor_new[str(data[str(i)]["Source Vendor"])] = 1
    
    vendor_new = dict(sorted(vendor_new.items(),key=lambda item: item[1], reverse=True))


    if str(data[str(i)]["Destination Vendor"]) in list(vendor_new.keys()):
        vendor_new[str(data[str(i)]["Destination Vendor"])] = vendor_new[str(data[str(i)]["Destination Vendor"])] + 1
    else:
        vendor_new[str(data[str(i)]["Destination Vendor"])] = 1
    
    vendor_new = dict(sorted(vendor_new.items(),key=lambda item: item[1], reverse=True))


    if str(data[str(i)]["Source Port"]) in list(sport_new.keys()):
        sport_new[str(data[str(i)]["Source Port"])] = sport_new[str(data[str(i)]["Source Port"])] + 1
    else:
        sport_new[str(data[str(i)]["Source Port"])] = 1
    
    sport_new = dict(sorted(sport_new.items(),key=lambda item: item[1], reverse=True))

    if str(data[str(i)]["Destination Port"]) in list(dport_new.keys()):
        dport_new[str(data[str(i)]["Destination Port"])] = dport_new[str(data[str(i)]["Destination Port"])] + 1
    else:
        dport_new[str(data[str(i)]["Destination Port"])] = 1
    
    dport_new = dict(sorted(dport_new.items(),key=lambda item: item[1], reverse=True))

    i = i + 1



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
        newance.append(key) # SRC IP
        newance.append(dst_new[key]) # IP OCCURENCE
        transfer4.append(newance)
    i = i+1

i=int(0)
for key in proto_new.keys():
    newance = []
    newance.append(key) # SRC IP
    newance.append(proto_new[key]) # IP OCCURENCE
    transfer5.append(newance)
    i = i+1

i=int(0)
for key in sport_new.keys():
    if i<10:
        newance = []
        newance.append(key) # SRC IP
        newance.append(sport_new[key]) # IP OCCURENCE
        transfer6.append(newance)
    i = i+1

i=int(0)
for key in src_new.keys():
    if i<10:
        newance = []
        newance.append(key) # SRC IP
        newance.append(src_new[key]) # IP OCCURENCE
        transfer.append(newance)
    i = i+1

i=int(0)
for key in dport_new.keys():
    if i<10:
        newance = []
        newance.append(key) # SRC IP
        newance.append(dport_new[key]) # IP OCCURENCE
        transfer7.append(newance)
    i = i+1


i = int(0)

for key in vendor_new.keys():
    #print(key)
    #print(vendor_new.keys())
    newance = []
    newance.append(key) # SRC IP
    newance.append(vendor_new[key]) # IP OCCURENCE
    transfer3.append(newance)
    i = i+1



tabling = tabulate(transfer, headers=["Source","Number of Packets with this Source"])
tabling2 = tabulate(transfer2, headers=["Src IP Address", "Dst IP Address", "Number of Packets Shared"])
tabling3 = tabulate(transfer3, headers=["Vendor Name","Number of Packets with the Vendor"])
tabling4 = tabulate(transfer4, headers=["Destination","Number of Packets with this Destination"])
tabling5 = tabulate(transfer5, headers=["Protocol","Number of Packets with this Protocol"])
tabling6 = tabulate(transfer6, headers=["Source Port","Number of Packets using this Port"])
tabling7 = tabulate(transfer7, headers=["Destination Port","Number of Packets using this Port"])
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