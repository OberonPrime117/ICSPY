# ////////////////// ALL IMPORTS ////////////////////////
from elasticsearch import Elasticsearch # SEARCHING
import requests # HTTP REQUEST
from OuiLookup import OuiLookup # ONLINE LOOKUP TO ADD TO OUR DB
from datetime import datetime # DATETIME
import json # JSON EXPORTS

import time # TIME FOR FUNCTIONS 
import asyncio # ASYNC CODE
from mac_vendor_lookup import MacLookup # ONLINE LOOKUP TO ADD TO OUR DB
import argparse # ARGUMENT FOR COMMAND

import sys # EXIT PROGRAM
import csv # CSV EXPORTS

# SCAPY PCAP INTERPRETER
from scapy.all import * # PCAP DATA
from scapy.layers.l2 import getmacbyip, Ether # PCAP DATA
from scapy.layers.inet import IP # PCAP DATA
from reloading import reloading
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
    #a = OuiLookup().query(macaddr)
    #print(macaddr)
    try:
        a = MacLookup().lookup(macaddr)
    except:
        with open("unknown-mac-address.txt", 'a', encoding='utf-8-sig') as f:
            f.write(macaddr+"\n")
        return "None"
    dicta = { "Mac Prefix": macaddr, "Vendor Name": a }
    with open("mac-vendors.json", 'r', encoding='utf-8-sig') as f:
        hello = json.load(f)
        hello = hello["value"]
    #print(hello)
    hello.append(dicta)
    abc = {"value" : dicta}
    filename = "runtime-exports/mac-vendors"+str(num)+".json"
    with open(filename, 'a', encoding='utf-8-sig') as f:
        json.dump(abc,f)
    return dicta["Vendor Name"]

def dstvendor(data,es,i):
    if data[str(i)]["Destination MAC"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        ELASTIC_PASSWORD = "M_R*tu-=C_98N2GZDoT_"
        es = Elasticsearch("https://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD), verify_certs=False)
        es.indices.refresh(index="mac-vendors")
        val = str(data[str(i)]["Destination MAC"])[0:8].upper()
        try:
            resp = es.get(index="mac-vendors",id=val)
            return resp['_source']["Vendor Name"]
        except:
            a = oui(str(data[str(i)]["Destination MAC"]),1)
            return a

def srcvendor(data,es,i):
    if str(data[str(i)]["Source MAC"]) == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
        ELASTIC_PASSWORD = "M_R*tu-=C_98N2GZDoT_"
        es = Elasticsearch("https://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD), verify_certs=False)
        es.indices.refresh(index="mac-vendors")
        val = str(data[str(i)]["Source MAC"])[0:8].upper()
        try:
            resp = es.get(index="mac-vendors",id=val)
            return resp['_source']["Vendor Name"]
        except:
            a = oui(str(data[str(i)]["Source MAC"]),2)
            return a

    
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

def export_data(i,img_static,csvfile,headerval,test,secondheaderval=None):
    if secondheaderval == None:
        header = [headerval,'Number of Packets']
    else:
        header = [headerval,secondheaderval,'Number of Packets']
    #with open(csvfile, 'w', encoding='UTF8', newline='') as f:
    #    writer = csv.writer(f)
    #    writer.writerow(header)

    # SEARCH AND POPULATE THE CSV

    searchp = { 
        "query" : { 
            "match_all" : {}
        }
    }

    resp = es.search(index=test, body=searchp)

    value = []

    if os.path.exists(csvfile):
        os.remove(csvfile)

    for j in resp["hits"]["hits"]:
        impact = es.get(index=test,id=j["_id"])

        b = []
        b.append(impact["_id"])

        if secondheaderval == None:
            pass
        else:
            b.append(impact["_source"]["Destination IP"])

        b.append(impact["_source"]["Number of Packets"])

        if os.path.isfile(csvfile):
            with open(csvfile, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(b)
        else:
            with open(csvfile, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(b)

    labels = []
    values = []
    print(i)
    if i>1:
        if secondheaderval == None:
            with open(csvfile, 'r') as csvf:
                lines = csv.reader(csvf, delimiter = ',')
                for row in lines:
                    labels.append(row[0])
                    values.append(int(row[1]))

            fig = go.Figure(data=[go.Pie(labels=labels, values=values, pull=[0.1, 0.1, 0.2, 0.1])])
            print(img_static)
            if i==1:
                fig.write_image(img_static)
            else:
                fig.write_image(img_static)

def delete(filename):
    try:
        os.remove(filename)
    except:
        pass

def dash(packet,data,packet_dict,i):
    ELASTIC_PASSWORD = "M_R*tu-=C_98N2GZDoT_"
    es = Elasticsearch("https://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD), verify_certs=False)
    start = time.time()
    #print(i)

    data[str(i)]["Source Port"] = srcport(packet_dict)
    finish = time.time()
    #print("SRC PORT",finish - start)

    start = time.time()
    data[str(i)]["Destination Port"] = dstport(packet_dict)
    finish = time.time()
    #print("DST PORT",finish - start)
    
    start = time.time()
    data[str(i)]["Source IP"] = srcip(packet, packet_dict)
    finish = time.time()
    #print("SRC IP",finish - start)
    
    start = time.time()
    data[str(i)]["Destination IP"] = dstip(packet, packet_dict)
    finish = time.time()
    #await asyncio.wait([data[str(i)]["Source Port"], data[str(i)]["Destination Port"],data[str(i)]["Source IP"],data[str(i)]["Destination IP"] ])
    #print("DST IP",finish - start)

    start = time.time()
    data[str(i)]["Destination MAC"] = dstmac(data,packet,packet_dict,i)
    finish = time.time()
    #print("DST MAC",finish - start)
    
    start = time.time()
    data[str(i)]["Source MAC"] = srcmac(data,packet,packet_dict,i)
    finish = time.time()
    #print("SRC MAC",finish - start)
    #await asyncio.wait([data[str(i)]["Destination MAC"],data[str(i)]["Source MAC"]])
    
    start = time.time()
    data[str(i)]["Destination Vendor"] = dstvendor(data,es,i)
    #print(data[str(i)]["Destination Vendor"])
    finish = time.time()
    #print("DST VENDOR",finish - start)
    
    start = time.time()
    data[str(i)]["Source Vendor"] = srcvendor(data,es,i)
    #print(data[str(i)]["Source Vendor"])
    finish = time.time()
    #print("SRC VENDOR",finish - start)

    #print(data)
    
    start = time.time()
    data[str(i)]["Protocol"] = proto(data, packet_dict, packet,i)
    finish = time.time()
    #print("PROTOCOL",finish - start)
    #await asyncio.wait([data[str(i)]["Destination Vendor"],data[str(i)]["Protocol"],data[str(i)]["Source Vendor"]])

    return data

#def index_doc(es,dicta,:
#    resp = es.index(index="mac-vendors",id=j,document=dicta)
 

# ////////////////// VARIABLE DECLARE ////////////////////////


ELASTIC_PASSWORD = "M_R*tu-=C_98N2GZDoT_"
es = Elasticsearch("https://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD), verify_certs=False)
es.options(ignore_status=[400,404]).indices.delete(index='srcdst')
es.options(ignore_status=[400,404]).indices.delete(index='srcip')
es.options(ignore_status=[400,404]).indices.delete(index='dstip')
es.options(ignore_status=[400,404]).indices.delete(index='vendors')
es.options(ignore_status=[400,404]).indices.delete(index='protocol')
es.options(ignore_status=[400,404]).indices.delete(index='srcport')
es.options(ignore_status=[400,404]).indices.delete(index='dstport')

delete("static/dst-ip.png")
delete("static/dst-port.png")
delete("static/protocol.png")
delete("static/src-ip.png")
delete("static/src-port.png")
delete("static/vendor.png")
delete("results/pair-of-ip.csv")
delete("results/dst-ip.csv")
delete("results/dst-port.csv")
delete("results/protocol.csv")
delete("results/src-ip.csv")
delete("results/src-port.csv")
delete("results/vendor.csv")
#filep = select_file()
#print(filep)

parser = argparse.ArgumentParser()
parser.add_argument("-p", "--pcap", help = "Enter your pcap file")
args = parser.parse_args()
if args.pcap:
    packets = rdpcap(args.pcap)
else:
    sys.exit()

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
transfer1 = []
transfer2 = []
transfer3 = []
transfer4 = []
transfer5 = []
transfer6 = []
transfer7 = []
done = False
data = {}
#plt.show()


# ////////////////// LOADING ANIMATION ////////////////////////


start = time.time()
i = 0
j = 81291
for packet in packets:
    # print(i)
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
    
    start = time.time()
    
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
        resp = es.index(index="protocol", id=str(data[str(i)]["Protocol"]), document=a)
    except:
        dbody = {"Number of Packets" : 1}
        resp = es.index(index="protocol", id=str(data[str(i)]["Protocol"]), document=dbody)
        
    # ////////////////// RANKING SRC IP , DST IP ////////////////////////

    try:
        resp = es.get(index="srcdst",id=str(data[str(i)]["Source IP"]))
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        resp = es.index(index="srcdst", id=str(data[str(i)]["Source IP"]), document=a)
    except:
        dbody = {"Number of Packets" : 1, "Destination IP": str(data[str(i)]["Destination IP"])}
        resp = es.index(index="srcdst", id=str(data[str(i)]["Source IP"]), document=dbody)

    # ////////////////// RANKING SRC IP ////////////////////////

    try:
        resp = es.get(index="srcip",id=str(data[str(i)]["Source IP"]))
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        resp = es.index(index="srcip", id=str(data[str(i)]["Source IP"]), document=a)
    except:
        dbody = {"Number of Packets" : 1}
        resp = es.index(index="srcip", id=str(data[str(i)]["Source IP"]), document=dbody)

    # ////////////////// RANKING DST IP ////////////////////////

    try:
        resp = es.get(index="dstip",id=str(data[str(i)]["Destination IP"]))
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        resp = es.index(index="dstip", id=str(data[str(i)]["Destination IP"]), document=a)
    except:
        dbody = {"Number of Packets" : 1}
        resp = es.index(index="dstip", id=str(data[str(i)]["Destination IP"]), document=dbody)

    # ////////////////// RANKING SRC VENDOR ////////////////////////

    try:
        resp = es.get(index="vendors",id=str(data[str(i)]["Source Vendor"]))
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        resp = es.index(index="vendors", id=str(data[str(i)]["Source Vendor"]), document=a)
    except:
        dbody = {"Number of Packets" : 1}
        resp = es.index(index="vendors", id=str(data[str(i)]["Source Vendor"]), document=dbody)

    # ////////////////// RANKING DST VENDOR ////////////////////////

    try:
        resp = es.get(index="vendors",id=str(data[str(i)]["Destination Vendor"]))
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        resp = es.index(index="vendors", id=str(data[str(i)]["Destination Vendor"]), document=a)
    except:
        dbody = {"Number of Packets" : 1}
        resp = es.index(index="vendors", id=str(data[str(i)]["Destination Vendor"]), document=dbody)

    # ////////////////// RANKING SRC PORT ////////////////////////

    try:
        resp = es.get(index="srcport",id=str(data[str(i)]["Source Port"]))
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        resp = es.index(index="srcport", id=str(data[str(i)]["Source Port"]), document=a)
    except:
        dbody = {"Number of Packets" : 1}
        resp = es.index(index="srcport", id=str(data[str(i)]["Source Port"]), document=dbody)

    # ////////////////// RANKING DST PORT ////////////////////////

    try:
        resp = es.get(index="dstport",id=str(data[str(i)]["Destination Port"]))
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        resp = es.index(index="dstport", id=str(data[str(i)]["Destination Port"]), document=a)
    except:
        dbody = {"Number of Packets" : 1}
        resp = es.index(index="dstport", id=str(data[str(i)]["Destination Port"]), document=dbody)

    # ////////////////// VISUALISATION CODE ////////////////////////

    details = {"protocol": str(data[str(i)]["Protocol"]),"srcdst": str(data[str(i)]["Source IP"]), "srcip": str(data[str(i)]["Source IP"]), "dstip": str(data[str(i)]["Destination IP"]), "vendors": [str(data[str(i)]["Destination Vendor"]),str(data[str(i)]["Source Vendor"])], "srcport": str(data[str(i)]["Source Port"]), "dstport": str(data[str(i)]["Destination Port"]) }

    #es.index(index="pcap", id=i, document=details)

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

    i = i + 1


# ////////////////// EXPORT DATA ////////////////////////

# 1. SRC DST PAIR
# 2. SRC IP
# 3. DST IP
# 4. VENDOR
# 5. PROTOCOL
# 6. SRC PORT
# 7. DST PORT
# 8. SRC MAC
# 9. DST MAC





done = True
