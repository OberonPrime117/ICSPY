from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, rdpcap, PcapReader
from dotenv import dotenv_values
import json 
import socket 
from functions.rank import ranking

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "N/A"

def srcmac(packet_dict,i,es):

    h = list(packet_dict.keys())[0]
    
    try:
        a = packet_dict[h]["src"]
    except:
        a = ""

    ranking("srcmac",a,es)
    
def dstmac(packet_dict,i,es):
    
    h = list(packet_dict.keys())[0]
    
    try:
        a = packet_dict[h]["dst"]
    except:
        a = ""

    ranking("dstmac",a,es)

def proto(packet_dict, packet, i, es):

    if IP in packet_dict:
        a = proto_name_by_num(int(packet[IP].proto)) # 2
    else:
        #data["Protocol"] = "Other" # 2
        flag = 0
        y = packet.summary().split()
        for b in y:
            if b.isupper():
                a = b
                flag = 1
                continue
            elif flag == 0: 
                a = "Other" 
    
    if "(" in str(a) or ")" in str(a):
        a = a[1:]
        a = a[:-1]
    
    ranking("protocol",a,es)

def dstvendor(packet_dict,es):
    h = list(packet_dict.keys())[0]
    if "dst" in packet_dict[h] and packet_dict[h]["dst"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        
        #es.indices.refresh(index="mac-vendors")
        #val = str(data["Destination MAC"])[0:8].upper()
        try:
            ab = packet_dict[h]["dst"]
            val = str(ab).upper()
            resp = es.get(index="mac-vendors",id=val)
            a = resp['_source']["Vendor Name"]
        except:
            try:
                ab = packet_dict[h]["dst"]
                val = str(ab)[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)
                a = resp['_source']["Vendor Name"]
            except:
                abc = packet_dict
                filename = "runtime/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc,f)
                a = "N/A"
    
    ranking("vendors",a,es)

def srcvendor(packet_dict,es):

    h = list(packet_dict.keys())[0]
    if "src" in packet_dict[h] and packet_dict[h]["src"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        
        #es.indices.refresh(index="mac-vendors")
        #val = str(data["Destination MAC"])[0:8].upper()
        try:
            ab = packet_dict[h]["src"]
            val = str(ab).upper()
            resp = es.get(index="mac-vendors",id=val)
            a = resp['_source']["Vendor Name"]
        except:
            try:
                ab = packet_dict[h]["src"]
                val = str(ab)[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)
                a = resp['_source']["Vendor Name"]
            except:
                abc = packet_dict
                filename = "runtime/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc,f)
                a = "N/A"
    
    ranking("vendors",a,es)
    
def srcport(packet_dict, es):
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['sport']  

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['sport']

    else:
        a = "N/A"
    
    ranking("srcport",a,es)

def dstport(packet_dict, es):
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['dport']
        

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['dport']

    else:
        a = "N/A"
    
    ranking("dstport",a,es)

def ip(packet, packet_dict, es):
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
    
    ranking("srcip",a,es)

    try:
        if IP in packet:
                b = str(packet[IP].dst) # 1
        else:
            try:
                b = packet_dict["802.3"]["dst"] # 1
            except:
                b = packet[Ether].dst # 1
    except:
        try:
            b = packet_dict["802.3"]["dst"] # 1
        except:
            b = packet[Ether].dst # 1
    
    ranking("dstip",b,es)
    ranking("srcdst",a,es,b)