# ////////////////// ALL IMPORTS ////////////////////////
from elasticsearch import Elasticsearch # SEARCHING
import requests # HTTP REQUEST

from datetime import datetime # DATETIME
import json # JSON EXPORTS
import os
import time # TIME FOR FUNCTIONS 
import argparse # ARGUMENT FOR COMMAND


import sys # EXIT PROGRAM
import csv # CSV EXPORTS
import kaleido
# SCAPY PCAP INTERPRETER
from scapy.all import * # PCAP DATA
from scapy.layers.l2 import getmacbyip, Ether # PCAP DATA
from scapy.layers.inet import IP # PCAP DATA
from reloading import reloading
from dotenv import dotenv_values
from functions.export import export_data
# ///// VISUAL
import random
from matplotlib import pyplot as plt 
import numpy as np 
from matplotlib.animation import FuncAnimation 
import plotly.graph_objects as go
import numpy as np 
import pandas as pd 
import plotly.express as px
import networkx as nx

# ////////////////// ELASTICSEARCH  ////////////////////////

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
    
def work():
    #os.system("python3 delete-files.py")
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", help = "Enter your pcap file")
    args = parser.parse_args()
    if args.pcap:
        packets = rdpcap(args.pcap)
    else:
        sys.exit()
    packet_dict = {}
    i=1
    

    done = False
    data = {}
    #plt.show()


    # ////////////////// LOADING ANIMATION ////////////////////////

    #start = time.time()
    i = 0
    j = 81291

    for packet in packets:
        # print(i)
        start = time.process_time()
        #print(start)
        #start = time.process_time()
        print("COUNT - "+str(i))
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
        #print(packet)
        #print(packet.summary())
        #start = time.time()#start = time.time()
        
        ip_mac_src_dst = [] 
        route = ""
        data = {}
        data[str(i)] = {}
        data[str(i)]["Frame Number"] = str(i)
        mac_vendor_src = []
        mac_vendor_dst = []

        # ////////////////// MAIN FUNCTION ////////////////////////

        data = dash(packet,data,packet_dict,i)

        # ////////////////// RANKING PROTOCOL ////////////////////////

        try:
            resp = es.get(index="protocol",id=str(data[str(i)]["Protocol"]))
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index="protocol", id=str(data[str(i)]["Protocol"]), body=a)
        except:
            dbody = {"Number of Packets" : 1}
            resp = es.index(index="protocol", id=str(data[str(i)]["Protocol"]), body=dbody)
            
        # ////////////////// RANKING SRC IP , DST IP ////////////////////////

        try:
            resp = es.get(index="srcdst",id=str(data[str(i)]["Source IP"]))
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index="srcdst", id=str(data[str(i)]["Source IP"]), body=a)
        except:
            dbody = {"Number of Packets" : 1, "Destination IP": str(data[str(i)]["Destination IP"])}
            resp = es.index(index="srcdst", id=str(data[str(i)]["Source IP"]), body=dbody)

        # ////////////////// RANKING SRC IP ////////////////////////

        try:
            resp = es.get(index="srcip",id=str(data[str(i)]["Source IP"]))
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index="srcip", id=str(data[str(i)]["Source IP"]), body=a)
        except:
            dbody = {"Number of Packets" : 1}
            resp = es.index(index="srcip", id=str(data[str(i)]["Source IP"]), body=dbody)

        # ////////////////// RANKING DST IP ////////////////////////

        try:
            resp = es.get(index="dstip",id=str(data[str(i)]["Destination IP"]))
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index="dstip", id=str(data[str(i)]["Destination IP"]), body=a)
        except:
            dbody = {"Number of Packets" : 1}
            resp = es.index(index="dstip", id=str(data[str(i)]["Destination IP"]), body=dbody)

        # ////////////////// RANKING SRC VENDOR ////////////////////////

        try:
            resp = es.get(index="vendors",id=str(data[str(i)]["Source Vendor"]))
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index="vendors", id=str(data[str(i)]["Source Vendor"]), body=a)
        except:
            dbody = {"Number of Packets" : 1}
            resp = es.index(index="vendors", id=str(data[str(i)]["Source Vendor"]), body=dbody)

        # ////////////////// RANKING DST VENDOR ////////////////////////

        try:
            resp = es.get(index="vendors",id=str(data[str(i)]["Destination Vendor"]))
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index="vendors", id=str(data[str(i)]["Destination Vendor"]), body=a)
        except:
            dbody = {"Number of Packets" : 1}
            resp = es.index(index="vendors", id=str(data[str(i)]["Destination Vendor"]), body=dbody)

        # ////////////////// RANKING SRC PORT ////////////////////////

        try:
            resp = es.get(index="srcport",id=str(data[str(i)]["Source Port"]))
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index="srcport", id=str(data[str(i)]["Source Port"]), body=a)
        except:
            dbody = {"Number of Packets" : 1}
            resp = es.index(index="srcport", id=str(data[str(i)]["Source Port"]), body=dbody)

        # ////////////////// RANKING DST PORT ////////////////////////

        try:
            resp = es.get(index="dstport",id=str(data[str(i)]["Destination Port"]))
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index="dstport", id=str(data[str(i)]["Destination Port"]), body=a)
        except:
            dbody = {"Number of Packets" : 1}
            resp = es.index(index="dstport", id=str(data[str(i)]["Destination Port"]), body=dbody)

        # ////////////////// VISUALISATION CODE ////////////////////////

        # ////////////////// PAIR SRC-DST CSV //////////////////

        # ////////////////// SOURCE CSV //////////////////

        export_data(i,"static/src-ip.png","results/src-ip.csv","Source IP","srcip")
                
        # ////////////////// DESTINATION CSV //////////////////

        export_data(i,"static/dst-ip.png","results/dst-ip.csv","Destination IP","dstip")

        # ////////////////// VENDOR CSV //////////////////

        export_data(i,"static/vendor.png","results/vendor.csv","Vendor Name","vendors")

        # ////////////////// PROTOCOL CSV //////////////////

        export_data(i,"static/protocol.png","results/protocol.csv","Protocols","protocol")

        # ////////////////// SOURCE PORT CSV //////////////////

        export_data(i,"static/src-port.png","results/src-port.csv","Source Port","srcport")

        # ////////////////// DESTINATION PORT CSV //////////////////

        export_data(i,"static/dst-port.png","results/dst-port.csv","Destination Port","dstport")

        #print(time.process_time() - start)

        i = i + 1
    done = True

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "N/A"

def srcmac(data,packet,packet_dict,i):
    if str(data[str(i)]["Source IP"]) == "0.0.0.0":
        a = "00:21:6a:2d:3b:8e" # 3

    if "::" in str(data[str(i)]["Source IP"]) and "::" in str(data[str(i)]["Destination IP"]):
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
    if str(data[str(i)]["Destination IP"]) == "255.255.255.255":
        a = "ff:ff:ff:ff:ff:ff" # 4
    
    if "::" in str(data[str(i)]["Source IP"]) and "::" in str(data[str(i)]["Destination IP"]):
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
        a = protocol[str(data[str(i)]["Source Port"])]
        
    if str(data[str(i)]["Destination Port"]) in list(protocol.keys()):
        a = protocol[str(data[str(i)]["Destination Port"])]

    if "Ethernet" in list(packet_dict.keys()) and str(packet_dict["Ethernet"]["type"]) in list(ethertype.keys()):
        a = ethertype[str(packet_dict["Ethernet"]["type"])]
    
    if str(data[str(i)]["Source IP"]) == "0.0.0.0":
        a = "DHCP"
    
    return a

def oui(macaddr,num):
    with open("config/myfile.json", 'r', encoding='utf-8-sig') as f:
        hello = json.load(f)
        hello = hello["value"]
    #print(hello)
    hello.append(dicta)
    abc = {"value" : dicta}
    filename = "runtime/mac-vendors"+str(num)+".json"
    with open(filename, 'a', encoding='utf-8-sig') as f:
        json.dump(abc,f)
    return dicta["Vendor Name"]

def dstvendor(data,es,i):
    if data[str(i)]["Destination MAC"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        config = dotenv_values(".env")
        ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
        es =  Elasticsearch("http://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD))
        #es.indices.refresh(index="mac-vendors")
        #val = str(data[str(i)]["Destination MAC"])[0:8].upper()
        try:
            val = str(data[str(i)]["Destination MAC"]).upper()
            resp = es.get(index="mac-vendors",id=val)
            return resp['_source']["Vendor Name"]
        except:
            try:
                val = str(data[str(i)]["Destination MAC"])[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)
                return resp['_source']["Vendor Name"]
            except:
                abc = str(data[str(i)]["Destination MAC"]) + "\n"
                filename = "runtime/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc,f)
                return abc

def srcvendor(data,es,i):
    if str(data[str(i)]["Source MAC"]) == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        config = dotenv_values(".env")
        ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
        es =  Elasticsearch("http://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD))
        #es.indices.refresh(index="mac-vendors")
        #val = str(data[str(i)]["Source MAC"])[0:8].upper()
        try:
            val = str(data[str(i)]["Source MAC"]).upper()
            resp = es.get(index="mac-vendors",id=val)
            return resp['_source']["Vendor Name"]
        except:
            try:
                val = str(data[str(i)]["Source MAC"])[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)
                return resp['_source']["Vendor Name"]
            except:
                abc = str(data[str(i)]["Source MAC"]) + "\n"
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

def animatepi(i):
    new_sizes = []
    new_sizes = random.sample(sizes, len(sizes))
    print(new_sizes)
    ax.clear()
    ax.axis('equal')
    ax.pie(new_sizes, labels=labels, autopct='%1.1f%%', shadow=True, startangle=140) 

def dash(packet,data,packet_dict,i):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD))
    
    #start = time.process_time()
    data[str(i)]["Source Port"] = srcport(packet_dict)
    #print(time.process_time() - start)

    #start = time.process_time()
    data[str(i)]["Destination Port"] = dstport(packet_dict)
    #print(time.process_time() - start)

    #start = time.process_time()
    data[str(i)]["Source IP"] = srcip(packet, packet_dict)
    #print(time.process_time() - start)

    #start = time.process_time()
    data[str(i)]["Destination IP"] = dstip(packet, packet_dict)
    #print(time.process_time() - start)

    #start = time.process_time()
    data[str(i)]["Destination MAC"] = dstmac(data,packet,packet_dict,i)
    #print(time.process_time() - start)

    #start = time.process_time()
    data[str(i)]["Source MAC"] = srcmac(data,packet,packet_dict,i)
    #print(time.process_time() - start)

    #start = time.process_time()
    data[str(i)]["Destination Vendor"] = dstvendor(data,es,i)
    #print(time.process_time() - start)

    #start = time.process_time()
    data[str(i)]["Source Vendor"] = srcvendor(data,es,i)
    #print(time.process_time() - start)

    #start = time.process_time()
    data[str(i)]["Protocol"] = proto(data, packet_dict, packet,i)
    #print(time.process_time() - start)

    return data

# ////////////////// VARIABLE DECLARE ////////////////////////



# ////////////////// VARIABLE DECLARE ////////////////////////

config = dotenv_values(".env")
ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
es = Elasticsearch("http://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD))
es.options(ignore_status=[400,404]).indices.delete(index='srcip')
es.options(ignore_status=[400,404]).indices.delete(index='protocol')
es.options(ignore_status=[400,404]).indices.delete(index='srcdst')
es.options(ignore_status=[400,404]).indices.delete(index='dstport')
es.options(ignore_status=[400,404]).indices.delete(index='srcport')
es.options(ignore_status=[400,404]).indices.delete(index='dstip')
es.options(ignore_status=[400,404]).indices.delete(index='vendors')

protocol = {"bacnet" : "BACnet" , "dnp": "DNP3" ,  "mbap" : "Modbus TCP" }
ethertype = {"0x88a4" : "EtherCat", "0x8892" : "PROFINET"}
work()
