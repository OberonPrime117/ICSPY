# ////////////////// ALL IMPORTS ////////////////////////
from elasticsearch import Elasticsearch # SEARCHING
import requests # HTTP REQUEST

from datetime import datetime # DATETIME
import json # JSON EXPORTS
import os
import time # TIME FOR FUNCTIONS 
import argparse # ARGUMENT FOR COMMAND
from collections import defaultdict
import multiprocessing
import sys # EXIT PROGRAM
import csv # CSV EXPORTS

# SCAPY PCAP INTERPRETER
from scapy.all import * # PCAP DATA
from scapy.layers.l2 import getmacbyip, Ether # PCAP DATA
from scapy.layers.inet import IP # PCAP DATA
from reloading import reloading
from dotenv import dotenv_values
from functions.rank import *
from functions.delete import *
from functions.export import *

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
    start = time.process_time()
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", help = "Enter your pcap file")
    args = parser.parse_args()
    if args.pcap:
        packets = PcapReader(args.pcap)
    else:
        sys.exit()
    packet_dict = defaultdict(int)
    i=1
    

    done = False
    data = defaultdict(int)
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
        #print(packet.show2(dump=True).split('\n'))
        for line in packet.show2(dump=True).split('\n'):
            # print(line)
            if '###' in line:
                layer = line.strip('#[] ')
                packet_dict[layer] = defaultdict(int)
            elif '=' in line:
                key, val = line.split('=', 1)
                packet_dict[layer][key.strip()] = val.strip()
        #print(packet_dict)
        # ////////////////// RESET VALUES ////////////////////////

        route = ""
        data = defaultdict(int)
        data[str(i)] = defaultdict(int)
        data[str(i)]["Frame Number"] = str(i)

        # ////////////////// MAIN FUNCTION ////////////////////////

        data = dash(packet,data,packet_dict,i)

        # ////////////////// RANKING PROTOCOL ////////////////////////
        start = time.process_time()
        r1 = multiprocessing.Process(target=ranking , args=("protocol",str(data[str(i)]["Protocol"])))
        r1.start()
        r2 = multiprocessing.Process(target=ranking , args=("srcdst",str(data[str(i)]["Source IP"]),str(data[str(i)]["Destination IP"])))
        r2.start()
        r3 = multiprocessing.Process(target=ranking , args=("srcip",str(data[str(i)]["Source IP"])))
        r3.start()
        r4 = multiprocessing.Process(target=ranking , args=("dstip",str(data[str(i)]["Destination IP"])))
        r4.start()
        if str(data[str(i)]["Source Vendor"]) == None:
            pass
        else:
            r5 = multiprocessing.Process(target=ranking , args=("vendors",str(data[str(i)]["Source Vendor"])))
            r5.start()
        if str(data[str(i)]["Destination Vendor"]) == None:
            pass
        else:
            r6 = multiprocessing.Process(target=ranking , args=("vendors",str(data[str(i)]["Destination Vendor"])))
            r6.start()
        r7 = multiprocessing.Process(target=ranking , args=("srcport",str(data[str(i)]["Source Port"])))
        r7.start()
        r8 = multiprocessing.Process(target=ranking , args=("dstport",str(data[str(i)]["Destination Port"])))
        r8.start()

        r1.join()
        r2.join()
        r3.join()
        r4.join()
        if str(data[str(i)]["Source Vendor"]) == None:
            pass
        else:
            r5.join()
        if str(data[str(i)]["Destination Vendor"]) == None:
            pass
        else:
            r6.join()
        r7.join()
        r8.join()
        #print(time.process_time() - start)
        #start = time.process_time()
        if i%200==0:
            p1 = multiprocessing.Process(target=export_data , args=("static/src-ip.png","results/src-ip.csv","srcip"))
            p1.start()
            p2 = multiprocessing.Process(target=export_data , args=("static/dst-ip.png","results/dst-ip.csv","dstip"))
            p2.start()
            p3 = multiprocessing.Process(target=export_data , args=("static/vendor.png","results/vendor.csv","vendors"))
            p3.start()
            p4 = multiprocessing.Process(target=export_data , args=("static/protocol.png","results/protocol.csv","protocol"))
            p4.start()
            p5 = multiprocessing.Process(target=export_data , args=("static/src-port.png","results/src-port.csv","srcport"))
            p5.start()
            p6 = multiprocessing.Process(target=export_data , args=("static/dst-port.png","results/dst-port.csv","dstport"))
            p6.start()

            p1.join()
            p2.join()
            p3.join()
            p4.join()
            p5.join()
            p6.join()

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

def dstvendor(data,es,i):
    start = time.process_time()
    if data[str(i)]["Destination MAC"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        config = dotenv_values(".env")
        ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
        es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))
        #es.indices.refresh(index="mac-vendors")
        #val = str(data[str(i)]["Destination MAC"])[0:8].upper()

        with open("config/ignore.json", 'r', encoding='utf-8-sig') as f:
            hello = json.load(f)
            for h in hello:
                h = h["Mac Address"]
                if h == str(data[str(i)]["Destination MAC"]):
                    #print(time.process_time() - start)
                    return None

        try:
            val = str(data[str(i)]["Destination MAC"]).upper()
            resp = es.get(index="mac-vendors",id=val)
            #print(time.process_time() - start)
            return resp['_source']["Vendor Name"]
        except:
            try:
                val = str(data[str(i)]["Destination MAC"])[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)
                #print(time.process_time() - start)
                return resp['_source']["Vendor Name"]
            except:
                abc = str(data[str(i)]["Destination MAC"]) + "\n"
                filename = "runtime/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc,f)
                #print(time.process_time() - start)
                return abc

def srcvendor(data,es,i):
    start = time.process_time()
    if str(data[str(i)]["Source MAC"]) == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        config = dotenv_values(".env")
        ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
        es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))
        #es.indices.refresh(index="mac-vendors")
        #val = str(data[str(i)]["Source MAC"])[0:8].upper()

        with open("config/ignore.json", 'r', encoding='utf-8-sig') as f:
            hello = json.load(f)
            for h in hello:
                h = h["Mac Address"]
                if h == str(data[str(i)]["Source MAC"]):
                    #print(time.process_time() - start)
                    return None

        try:
            val = str(data[str(i)]["Source MAC"]).upper()
            resp = es.get(index="mac-vendors",id=val)
            #print(time.process_time() - start)
            return resp['_source']["Vendor Name"]
        except:
            try:
                val = str(data[str(i)]["Source MAC"])[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)
                #print(time.process_time() - start)
                return resp['_source']["Vendor Name"]
            except:
                abc = str(data[str(i)]["Source MAC"]) + "\n"
                filename = "runtime/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc,f)
                #print(time.process_time() - start)
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

def dash(packet,data,packet_dict,i):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))
    
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

#print(multiprocessing.cpu_count())
#os.system("python3 delete-files.py")
protocol = {"bacnet" : "BACnet" , "dnp": "DNP3" ,  "mbap" : "Modbus TCP" }
ethertype = {"0x88a4" : "EtherCat", "0x8892" : "PROFINET"}

if __name__ == "__main__":
    # creating processes
    p1 = multiprocessing.Process(target=iterate_deletecsv)
    p2 = multiprocessing.Process(target=work)
    p3 = multiprocessing.Process(target=resetelk)
     # iterate export
    p3.start() # start deleting elasticsearch index
    p1.start() # delete csv
    p3.join() # elasticsearch should finish deleting
    p1.join()
    p2.start() # start reading pcap
    
    p2.join()
    print("Done!")