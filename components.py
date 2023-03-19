from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, rdpcap, PcapReader
from dotenv import dotenv_values
import json 
import socket 

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "N/A"

def srcmac(data,packet,packet_dict,i):
    if str(data["Source IP"]) == "0.0.0.0":
        a = "00:21:6a:2d:3b:8e" # 3

    if "::" in str(data["Source IP"]) and "::" in str(data["Destination IP"]):
        a = str(packet[Ether].src) # 3
    
    else:
        try:
            a = packet[Ether].src
        except:
            try:
                a =  packet_dict["802.3"]["src"] # 3
            except:
                a = "" # 3
    #print(a)
    return a
    
def dstmac(data,packet,packet_dict,i):
    if str(data["Destination IP"]) == "255.255.255.255":
        a = "ff:ff:ff:ff:ff:ff" # 4
    
    if "::" in str(data["Source IP"]) and "::" in str(data["Destination IP"]):
        a = str(packet[Ether].dst) # 4
    
    else:
        try:
            a = packet[Ether].dst # 4
        except:
            try:
                a = packet_dict["802.3"]["dst"]
            except:
                a = ""
    #print(a)
    return a

def proto(data, packet_dict, packet,i):
    if IP in packet:
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
    
    if str(data["Source IP"]) == "0.0.0.0":
        a = "DHCP"
    
    return a

def dstvendor(data,es):

    if data["Destination MAC"] == 'ff:ff:ff:ff:ff:ff':
        return "Broadcast"
    else:
        
        #es.indices.refresh(index="mac-vendors")
        #val = str(data["Destination MAC"])[0:8].upper()
        try:
            val = str(data["Destination MAC"]).upper()
            resp = es.get(index="mac-vendors",id=val)
            return resp['_source']["Vendor Name"]
        except:
            try:
                val = str(data["Destination MAC"])[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)
                return resp['_source']["Vendor Name"]
            except:
                abc = str(data["Destination MAC"]) + "\n"
                filename = "runtime/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc,f)
                return abc

def srcvendor(data,es):

    if str(data["Source MAC"]) == 'ff:ff:ff:ff:ff:ff':
        return "Broadcast"
    else:

        try:
            val = str(data["Source MAC"]).upper()
            resp = es.get(index="mac-vendors",id=val)
            return resp['_source']["Vendor Name"]
        except:
            try:
                val = str(data["Source MAC"])[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)
                return resp['_source']["Vendor Name"]
            except:
                abc = str(data["Source MAC"]) + "\n"
                filename = "runtime/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc,f)
                return abc

    
def srcport(packet_dict):
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['sport']  

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['sport']

    else:
        a = "N/A"
    return a

def dstport(packet_dict):
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['dport']
        

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['dport']

    else:
        a = "N/A"
    return a

def srcip(packet, packet_dict):
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

def dstip(packet, packet_dict):
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