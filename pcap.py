# ////////////////// ALL IMPORTS ////////////////////////
from elasticsearch import Elasticsearch # SEARCHING
import requests # HTTP REQUEST
from dp import *
from datetime import datetime # DATETIME
import json # JSON EXPORTS
import os
import time # TIME FOR FUNCTIONS 
import argparse # ARGUMENT FOR COMMAND
from collections import defaultdict
import multiprocessing
import sys # EXIT PROGRAM
import csv # CSV EXPORTS
import dpkt
# SCAPY PCAP INTERPRETER
from scapy.all import * # PCAP DATA
from scapy.layers.l2 import getmacbyip, Ether # PCAP DATA
from scapy.layers.inet import IP # PCAP DATA
from reloading import reloading
from dotenv import dotenv_values
from functions.rank import *
from functions.delete import *
from functions.export import *
from dpkt.ip import IP, IP_PROTO_UDP
from dpkt.udp import UDP
from dpkt.tcp import TCP
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
        f = open(args.pcap,'rb')
        packets = dpkt.pcap.Reader(f)
    else:
        sys.exit()
    packet_dict = defaultdict(int)
    i=1
    
    data = {}
    #plt.show()


    # ////////////////// LOADING ANIMATION ////////////////////////

    #start = time.time()
    i = 0

    for ts,buf in packets:
        #print(ts)
        #print(buf)
        # print(i)
        #start = time.process_time()
        #print(start)
        #start = time.process_time()
        print("COUNT - "+str(i))


        # ////////////////// RESET VALUES ////////////////////////

        dbody = {"Frame Number":str(i)}
        es.index(index="pcap", id="pcap", document=dbody)

        #data["Frame Number"] = str(i)
        #print("Hello")

        # ////////////////// MAIN FUNCTION ////////////////////////

        dash(buf)

        es.indices.refresh(index="pcap")
        resp = es.get(index="pcap",id="pcap")
        dmac = resp["_source"]["Destination MAC"]
        smac = resp["_source"]["Source MAC"]
        dip = resp["_source"]["Destination IP"]
        sip = resp["_source"]["Source IP"]
        dport = resp["_source"]["Destination Port"]
        sport = resp["_source"]["Source Port"]
        proto_val = resp["_source"]["Protocol"]
        dvendor = resp["_source"]["Destination Vendor"]
        svendor = resp["_source"]["Source Vendor"]

        # ////////////////// RANKING PROTOCOL ////////////////////////
        start = time.process_time()
        r1 = multiprocessing.Process(target=ranking , args=("protocol",proto_val))
        r1.start()
        r2 = multiprocessing.Process(target=ranking , args=("srcdst",sip,dip))
        r2.start()
        r3 = multiprocessing.Process(target=ranking , args=("srcip",sip))
        r3.start()
        r4 = multiprocessing.Process(target=ranking , args=("dstip",dip))
        r4.start()
        if str(data["Source Vendor"]) == None:
            pass
        else:
            r5 = multiprocessing.Process(target=ranking , args=("vendors",svendor))
            r5.start()
        if str(data["Destination Vendor"]) == None:
            pass
        else:
            r6 = multiprocessing.Process(target=ranking , args=("vendors",dvendor))
            r6.start()
        r7 = multiprocessing.Process(target=ranking , args=("srcport",sport))
        r7.start()
        r8 = multiprocessing.Process(target=ranking , args=("dstport",dport))
        r8.start()

        r1.join()
        r2.join()
        r3.join()
        r4.join()
        if svendor == None:
            pass
        else:
            r5.join()
        if dvendor == None:
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

def dstvendor():
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    es.indices.refresh(index="pcap")
    resp = es.get(index="pcap",id="pcap")
    dbody = resp["_source"]
    data = resp["_source"]["Destination MAC"]
    
    start = time.process_time()
    
    if str(data) == 'ff:ff:ff:ff:ff:ff':
        dbody["Destination Vendor"] = "Broadcast"
        resp = es.index(index="pcap", id="pcap", document=dbody)
        
    else:
        #with open("config/ignore.json", 'r', encoding='utf-8-sig') as f:
        #    hello = json.load(f)
        #    for h in hello:
        #        h = h["Mac Address"]
        #        if h == str(data):
        #            dbody["Destination Vendor"] = "None"
        #            resp = es.index(index="pcap", id="pcap", document=dbody)

        try:
            val = str(data).upper()
            resp = es.get(index="mac-vendors",id=val)

            dbody["Destination Vendor"] = resp['_source']["Vendor Name"]
            resp = es.index(index="pcap", id="pcap", document=dbody)
        except:
            try:
                val = str(data)[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)
                
                dbody["Destination Vendor"] = resp['_source']["Vendor Name"]
                resp = es.index(index="pcap", id="pcap", document=dbody)
            except:
                abc = str(data) + "\n"

                filename = "runtime/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc,f)
                
                dbody["Destination Vendor"] = "N/A"
                resp = es.index(index="pcap", id="pcap", document=dbody)

def srcvendor():
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    es.indices.refresh(index="pcap")
    resp = es.get(index="pcap",id="pcap")
    dbody = resp["_source"]
    data = resp["_source"]["Source MAC"]

    start = time.process_time()
    if str(data) == 'ff:ff:ff:ff:ff:ff':
        dbody["Source Vendor"] = "Broadcast"
        resp = es.index(index="pcap", id="pcap", document=dbody)
    else:

        #with open("config/ignore.json", 'r', encoding='utf-8-sig') as f:
        #    hello = json.load(f)
        #    for h in hello:
        #        h = h["Mac Address"]
        #        if h == str(data):
        #            dbody["Source Vendor"] = "None"
        #            resp = es.index(index="pcap", id="pcap", document=dbody)

        try:
            val = str(data).upper()
            resp = es.get(index="mac-vendors",id=val)

            dbody["Source Vendor"] = resp['_source']["Vendor Name"]
            resp = es.index(index="pcap", id="pcap", document=dbody)

        except:
            try:
                val = str(data)[0:8].upper()
                resp = es.get(index="mac-vendors",id=val)

                dbody["Source Vendor"] = resp['_source']["Vendor Name"]
                resp = es.index(index="pcap", id="pcap", document=dbody)
            except:
                abc = str(data) + "\n"

                filename = "runtime/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc,f)
                
                dbody["Source Vendor"] = "N/A"
                resp = es.index(index="pcap", id="pcap", document=dbody)
    
def srcmac(buf):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    eth = dpkt.ethernet.Ethernet(buf)

    resp = es.get(index="pcap",id="pcap")
    dbody = resp["_source"]
    dbody["Source MAC"] = mac_addr(eth.src)
    resp = es.index(index="pcap", id="pcap", document=dbody)
    
def dstmac(buf):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    eth = dpkt.ethernet.Ethernet(buf)

    resp = es.get(index="pcap",id="pcap")
    dbody = resp["_source"]
    dbody["Destination MAC"] = mac_addr(eth.dst)
    resp = es.index(index="pcap", id="pcap", document=dbody)

def proto(buf):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    eth = dpkt.ethernet.Ethernet(buf)

    if not isinstance(eth.data, dpkt.ip.IP):
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Protocol"] = eth.data.__class__.__name__
        resp = es.index(index="pcap", id="pcap", document=dbody)

    else:
        ip = eth.data
        proto = ip.get_proto(ip.p).__name__
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Protocol"] = proto
        resp = es.index(index="pcap", id="pcap", document=dbody)
    
def srcport(buf):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data

    if type(ip.data) == TCP:
        tcp = ip.data
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Source Port"] = tcp.sport
        resp = es.index(index="pcap", id="pcap", document=dbody)

    if type(ip.data) == UDP:
        udp = ip.data
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Source Port"] = udp.sport
        resp = es.index(index="pcap", id="pcap", document=dbody)


def dstport(buf):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data

    if type(ip.data) == TCP:
        tcp = ip.data
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Destination Port"] = tcp.dport
        resp = es.index(index="pcap", id="pcap", document=dbody)
    
    if type(ip.data) == UDP:
        udp = ip.data
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Destination Port"] = udp.dport
        resp = es.index(index="pcap", id="pcap", document=dbody)


def srcip(buf):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data

    if not isinstance(eth.data, dpkt.ip.IP):
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Source IP"] = mac_addr(eth.src)
        resp = es.index(index="pcap", id="pcap", document=dbody)
    else:
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Source IP"] = inet_to_str(ip.src)
        resp = es.index(index="pcap", id="pcap", document=dbody)

def dstip(buf):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data

    if not isinstance(eth.data, dpkt.ip.IP):
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Destination IP"] = mac_addr(eth.dst)
        resp = es.index(index="pcap", id="pcap", document=dbody)
    else:
        resp = es.get(index="pcap",id="pcap")
        dbody = resp["_source"]
        dbody["Destination IP"] = inet_to_str(ip.dst)
        resp = es.index(index="pcap", id="pcap", document=dbody)

# buf, data, i
def dash(buf):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    #print("PQRS")
    #start = time.process_time()

    p6 = multiprocessing.Process(target=srcmac,args=(buf,))
    p6.start()
    p5 = multiprocessing.Process(target=dstmac,args=(buf,))
    p5.start()

    p1 = multiprocessing.Process(target=srcport,args=(buf,))
    p1.start()

    p2 = multiprocessing.Process(target=dstport,args=(buf,))
    p2.start()

    p3 = multiprocessing.Process(target=srcip,args=(buf,))
    p3.start()

    p4 = multiprocessing.Process(target=dstip,args=(buf,))
    p4.start()

    p7 = multiprocessing.Process(target=proto,args=(buf,))
    p7.start()

    p6.join()
    p5.join()
    
    p1.join()
    p2.join()
    p3.join()
    p4.join()
    p5.join()
    p7.join()
    
    resp = es.get(index="pcap",id="pcap")
    dbody = resp["_source"]
    dbody["Source Vendor"] = srcvendor()
    resp = es.index(index="pcap", id="pcap", document=dbody)

    resp = es.get(index="pcap",id="pcap")
    dbody = resp["_source"]
    dbody["Destination Vendor"] = dstvendor()
    resp = es.index(index="pcap", id="pcap", document=dbody)

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