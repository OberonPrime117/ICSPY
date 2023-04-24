import multiprocessing
from flask import Flask, render_template
import os
from flask import request
from multiprocessing import Pool, Process
import webbrowser
import argparse
from elasticsearch import Elasticsearch  # SEARCHING
import json
from dotenv import dotenv_values
import sys
import plotly
import requests
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, rdpcap, PcapReader
import scapy.contrib.modbus as mb
import socket
import threading
import csv
import uuid
import plotly.graph_objects as go
import plotly.offline as pyo
from scapy.all import *
import networkx as nx
from pyvis.network import Network
import pandas as pd
from threading import Timer
from matplotlib import pyplot as plt
import threading
import glob
import networkx as nx
import matplotlib.pyplot as plt
import mpld3
import plotly.express as px


def search(csvfile, test, es):
    searchp = {
        "match_all": {}
    }

    resp = es.search(index=test, query=searchp)
    d = []
    if test == "srcdst":
        d.append(['Source', 'Destination', 'Number of Packets'])

    for j in resp["hits"]["hits"]:
        impact = es.get(index=test, id=j["_id"])

        b = []

        if test == "srcdst":
            trial = impact["_id"].split("--")
            b.append(trial[0])  # SOURCE
            b.append(trial[1])  # DESTINATION
        else:
            b.append(impact["_id"])
        b.append(impact["_source"]["Number of Packets"])
        d.append(b)

    for i in d:
        with open(csvfile, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(i)

def export(es):
    createme()
    p2 = threading.Thread(target=search, args=("results/src-ip.csv", "srcip", es))
    p3 = threading.Thread(target=search, args=("results/dst-ip.csv", "dstip", es))
    p4 = threading.Thread(target=search, args=("results/vendor.csv", "vendors", es))
    p5 = threading.Thread(target=search,
                          args=("results/protocol.csv", "protocol", es))
    p6 = threading.Thread(target=search,
                          args=("results/src-port.csv", "srcport", es))
    p2.start()
    p3.start()
    p4.start()
    p5.start()
    p6.start()
    search("results/dst-port.csv", "dstport", es)
    search("results/dst-mac.csv", "dstmac", es)
    search("results/src-mac.csv", "srcmac", es)
    search("results/src-dst.csv", "srcdst", es)
    p2.join()
    p3.join()
    p4.join()
    p5.join()
    p6.join()


# ranking("srcmac",a,es)
# case 1 - srcip 127.0.0.1 - 1
# case 2 - src dst - 
def ranking(esindex, esid, es, secondid=None):

    if secondid is None and esindex != "srcdst":
        try:
            # CHECKING IF THE ESID EXISTS ALREADY
            resp = es.get(index=esindex, id=esid)
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index=esindex, id=esid, body=a)
        except:
            # ESID DOES NOT EXIST
            a = {"Number of Packets": 1}
            resp = es.index(index=esindex, id=esid, body=a)
    elif esindex == "srcdst":
        eval = str(esid) + "--" + str(secondid)
        try:
            # CHECKING IF THE ESID EXISTS ALREADY
            resp = es.get(index=esindex, id=eval)
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index=esindex, id=eval, body=a)
        except:
            # ESID DOES NOT EXIST
            a = {"Number of Packets": 1}
            resp = es.index(index=esindex, id=eval, body=a)
    else:
        print("ERROR IN RANKING - LINE 105")
        sys.exit()


def iterate_deletecsv(filename):
    try:
        os.remove(filename)
    except:
        pass


def delete():
    # config = dotenv_values(".env")
    # ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    # ELASTIC_PASSWORD = "XQs+_IZI=JV7toA7PKrw"
    # es =  Elasticsearch("http://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD))

    p1 = threading.Thread(target=iterate_deletecsv, args=("results/dst-ip.csv",))
    p2 = threading.Thread(target=iterate_deletecsv, args=("results/dst-port.csv",))
    p3 = threading.Thread(target=iterate_deletecsv, args=("results/protocol.csv",))
    p4 = threading.Thread(target=iterate_deletecsv, args=("results/src-ip.csv",))
    p5 = threading.Thread(target=iterate_deletecsv, args=("results/src-port.csv",))
    p6 = threading.Thread(target=iterate_deletecsv, args=("results/src-mac.csv",))
    p1.start()
    p2.start()
    p3.start()
    p4.start()
    p5.start()
    p6.start()
    iterate_deletecsv("results/dst-mac.csv", )
    iterate_deletecsv("results/vendor.csv", )
    iterate_deletecsv("results/src-dst.csv", )
    p1.join()
    p2.join()
    p3.join()
    p4.join()
    p5.join()
    p6.join()


def proto_name_by_num(proto_num):
    for name, num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "N/A"


def srcmac(packet_dict, i, es):
    h = list(packet_dict.keys())[0]

    try:
        a = packet_dict[h]["src"]
    except:
        a = ""

    ranking("srcmac", a, es)


def dstmac(packet_dict, i, es):
    h = list(packet_dict.keys())[0]

    try:
        a = packet_dict[h]["dst"]
    except:
        a = ""

    ranking("dstmac", a, es)


def proto(packet_dict, packet, i, es, sp, dp, mapping):
    # print(packet_dict)
    if IP in packet_dict:
        a = proto_name_by_num(int(packet[IP].proto))  # 2
    else:
        # data["Protocol"] = "Other" # 2
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

    if len(a) < 3:
        ph = set(['TCP', 'UDP', 'LLC', 'STP', 'ARP', 'CIP'])
        z = set(y)
        g = ph.intersection(z)
        # print(g)
        a = list(g)[-1]
        # print(list(g)[-1])

    for bh in y:
        if '.' in str(bh):
            d = bh.split(":")
            if 'ssdp' in d:
                a = "SSDP"
    if 'NBTSession' in y:
        a = "SAMBA"
    elif mb.ModbusADUResponse in packet:
        a = "ModbusTCP"
    elif sp in list(mapping.keys()):
        a = mapping[sp]
    elif dp in list(mapping.keys()):
        a = mapping[dp]

    #print(sp)
    #print(dp)
    #print(y)
    ranking("protocol", a, es)


def dstvendor(packet_dict, es):
    h = list(packet_dict.keys())[0]
    if "dst" in packet_dict[h] and packet_dict[h]["dst"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:

        # es.indices.refresh(index="mac-vendors")
        # val = str(data["Destination MAC"])[0:8].upper()
        try:
            ab = packet_dict[h]["dst"]
            val = str(ab).upper()
            resp = es.get(index="mac-vendors", id=val)
            a = resp['_source']["Vendor Name"]
        except:
            try:
                ab = packet_dict[h]["dst"]
                val = str(ab)[0:8].upper()
                resp = es.get(index="mac-vendors", id=val)
                a = resp['_source']["Vendor Name"]
            except:
                abc = packet_dict
                filename = "backup/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc, f)
                a = "N/A"
    
    if 'SNAP' in list(packet_dict.keys()):
        a = str(packet_dict['SNAP']['OUI']).split("(")[0]
        #print(a)

    ranking("vendors", a, es)


def srcvendor(packet_dict, es):
    h = list(packet_dict.keys())[0]
    if "src" in packet_dict[h] and packet_dict[h]["src"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:

        # es.indices.refresh(index="mac-vendors")
        # val = str(data["Destination MAC"])[0:8].upper()
        try:
            ab = packet_dict[h]["src"]
            val = str(ab).upper()
            resp = es.get(index="mac-vendors", id=val)
            a = resp['_source']["Vendor Name"]
        except:
            try:
                ab = packet_dict[h]["src"]
                val = str(ab)[0:8].upper()
                resp = es.get(index="mac-vendors", id=val)
                a = resp['_source']["Vendor Name"]
            except:
                abc = packet_dict
                filename = "backup/data.json"
                with open(filename, 'a', encoding='utf-8-sig') as f:
                    json.dump(abc, f)
                a = "N/A"

    ranking("vendors", a, es)


def srcport(packet_dict, packet, es):
    
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['sport']

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['sport']

    else:
        a = "N/A"
    
    y = packet.summary().split()
    for b in y:
        if '.' in b and ':' in b:
            d = b.split(":")
            a = d[1]

    ranking("srcport", a, es)
    return a


def dstport(packet_dict, packet, es):
    
    
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['dport']

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['dport']

    else:
        a = "N/A"

    y = packet.summary().split()
    for b in y:
        if '.' in b and ':' in b:
            d = b.split(":")
            a = d[1]
    
    ranking("dstport", a, es)
    return a


def ip(packet, packet_dict, es):
    try:

        if IP in packet:
            a = str(packet[IP].src)  # 0
        else:
            try:
                a = packet_dict["802.3"]["src"]  # 0
            except:
                a = packet[Ether].src  # 0
    except:
        try:
            a = packet_dict["802.3"]["src"]  # 0
        except:
            a = packet[Ether].src  # 0

    ranking("srcip", a, es)

    try:
        if IP in packet:
            b = str(packet[IP].dst)  # 1
        else:
            try:
                b = packet_dict["802.3"]["dst"]  # 1
            except:
                b = packet[Ether].dst  # 1
    except:
        try:
            b = packet_dict["802.3"]["dst"]  # 1
        except:
            b = packet[Ether].dst  # 1

    ranking("dstip", b, es)
    # print(a)
    # print(b)
    ranking("srcdst", a, es, b)


def work(es, packets):
    global i
    i = 1

    for packet in packets:
        # print(i)

        packet_dict = {}
        data = {}
        heights = []
        data["Frame Number"] = str(i)

        print("COUNT - " + str(i))

        for line in packet.show2(dump=True).split('\n'):
            if '###' in line:
                layer = line.strip('#[] ')
                heights.append(layer)
                packet_dict[layer] = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                packet_dict[layer][key.strip()] = val.strip()

        # ////////////////// MAIN FUNCTION ////////////////////////
        # print(list(packet_dict.keys()))

        # p1 = threading.Thread(target=dash,args=(packet,packet_dict,i,es))
        dash(packet, packet_dict, i, es)

        # p1.start()
        if len(str(i)) <= 3:
            val = 10 ** int(len(str(i)))
            val = val / 2
            if i % val == 0:
                export(es)
                networkgraph()

            # 3 digits - 100 , 400 45455
        else:
            # 5000 , 10,000
            val = 10 ** int(len(str(i)))
            val = val / 5
            if i % val == 0:
                export(es)
                networkgraph()

        # p1.join()

        # rankme(es,data)
        i = i + 1


def dash(packet, packet_dict, i, es):
    mapping = {
        "20000":"DNP3",
        "502": "ModbusTCP",
        "47808": "BACnet",
        "34980": "EtherCAT",
        "55000": "FL-net",
        "55001": "FL-net",
        "55002": "FL-net",
        "55003": "FL-net",
        "102": "ICCP",
        "4000": "ROC Plus",
        "4840": "OPC UA Discovery Server",
        
        "44818": "EtherNet/IP",
        "34962": "PROFINET",
        "34963": "PROFINET",
        "34964": "PROFINET",
        "9600": "OMRON FINS",
        "4000": "EMERSON FISHER",
        "55555": "FOXBORO FOXAPI",
        "45678": "FOXBORO AIMAPI",
        "1541": "FOXBORO INFORMIX",
        "18000": "ICONICS",
        "11001": "MetaSys N1", 
        "10307": "ABB Ranger 2003",
        "10311": "ABB Ranger 2003",
        "10364": "ABB Ranger 2003",
        "10365": "ABB Ranger 2003",
        "10407": "ABB Ranger 2003",
        "10409": "ABB Ranger 2003",
        "10410": "ABB Ranger 2003",
        "10412": "ABB Ranger 2003",
        "10414": "ABB Ranger 2003",
        "10415": "ABB Ranger 2003",
        "10428": "ABB Ranger 2003",
        "10431": "ABB Ranger 2003",
        "10432": "ABB Ranger 2003",
        "10447": "ABB Ranger 2003",
        "10449": "ABB Ranger 2003",
        "10450": "ABB Ranger 2003",
        "12316": "ABB Ranger 2003",
        "12645": "ABB Ranger 2003",
        "12647": "ABB Ranger 2003",
        "12648": "ABB Ranger 2003",
        "13722": "ABB Ranger 2003",
        "13724": "ABB Ranger 2003",
        "13782": "ABB Ranger 2003",
        "13783": "ABB Ranger 2003",
        "38589": "ABB Ranger 2003",
        "38593": "ABB Ranger 2003",
        "38600": "ABB Ranger 2003",
        "38971": "ABB Ranger 2003",
        "39129": "ABB Ranger 2003",
        "39278": "ABB Ranger 2003",
        "5450": "PI SERVER OSISOFT",
        "50001": "SEIMENS SPECTRUM POWER TG",
        "50002": "SEIMENS SPECTRUM POWER TG",
        "50003": "SEIMENS SPECTRUM POWER TG",
        "50004": "SEIMENS SPECTRUM POWER TG",
        "50005": "SEIMENS SPECTRUM POWER TG",
        "50006": "SEIMENS SPECTRUM POWER TG",
        "50007": "SEIMENS SPECTRUM POWER TG",
        "50008": "SEIMENS SPECTRUM POWER TG",
        "50009": "SEIMENS SPECTRUM POWER TG",
        "50010": "SEIMENS SPECTRUM POWER TG",
        "50011": "SEIMENS SPECTRUM POWER TG",
        "50012": "SEIMENS SPECTRUM POWER TG",
        "50013": "SEIMENS SPECTRUM POWER TG",
        "50014": "SEIMENS SPECTRUM POWER TG",
        "50015": "SEIMENS SPECTRUM POWER TG",
        "50016": "SEIMENS SPECTRUM POWER TG",
        "50018": "SEIMENS SPECTRUM POWER TG",
        "50019": "SEIMENS SPECTRUM POWER TG",
        "50020": "SEIMENS SPECTRUM POWER TG",
        "50021": "SEIMENS SPECTRUM POWER TG",
        "50025": "SEIMENS SPECTRUM POWER TG",
        "50026": "SEIMENS SPECTRUM POWER TG",
        "50027": "SEIMENS SPECTRUM POWER TG",
        "50028": "SEIMENS SPECTRUM POWER TG",
        "50110": "SEIMENS SPECTRUM POWER TG",
        "50111": "SEIMENS SPECTRUM POWER TG",
        "38000": "SNC GENe",
        "38001": "SNC GENe",
        "38011": "SNC GENe",
        "38012": "SNC GENe",
        "38014": "SNC GENe",
        "38015": "SNC GENe",
        "38200": "SNC GENe",
        "38210": "SNC GENe",
        "38301": "SNC GENe",
        "38400": "SNC GENe",
        "38700": "SNC GENe",
        "62900": "SNC GENe",
        "62911": "SNC GENe",
        "62924": "SNC GENe",
        "62930": "SNC GENe",
        "62938": "SNC GENe",
        "62956": "SNC GENe",
        "62957": "SNC GENe",
        "62963": "SNC GENe",
        "62981": "SNC GENe",
        "62982": "SNC GENe",
        "62985": "SNC GENe",
        "62992": "SNC GENe",
        "63012": "SNC GENe",
        "63027": "SNC GENe",
        "63028": "SNC GENe",
        "63029": "SNC GENe",
        "63030": "SNC GENe",
        "63031": "SNC GENe",
        "63032": "SNC GENe",
        "63033": "SNC GENe",
        "63034": "SNC GENe",
        "63035": "SNC GENe",
        "63036": "SNC GENe",
        "63041": "SNC GENe",
        "63075": "SNC GENe",
        "63079": "SNC GENe",
        "63082": "SNC GENe",
        "63088": "SNC GENe",
        "63094": "SNC GENe",
        "65443": "SNC GENe",
        "5050": "TELVENT OASyS DNA",
        "5051": "TELVENT OASyS DNA",
        "5052": "TELVENT OASyS DNA",
        "5065": "TELVENT OASyS DNA",
        "12135": "TELVENT OASyS DNA",
        "12136": "TELVENT OASyS DNA",
        "12137": "TELVENT OASyS DNA",
        "56001": "TELVENT OASyS DNA",
        "56002": "TELVENT OASyS DNA",
        "56003": "TELVENT OASyS DNA",
        "56004": "TELVENT OASyS DNA",
        "56005": "TELVENT OASyS DNA",
        "56006": "TELVENT OASyS DNA",
        "56007": "TELVENT OASyS DNA",
        "56008": "TELVENT OASyS DNA",
        "56009": "TELVENT OASyS DNA",
        "56010": "TELVENT OASyS DNA",
        "56011": "TELVENT OASyS DNA",
        "56012": "TELVENT OASyS DNA",
        "56013": "TELVENT OASyS DNA",
        "56014": "TELVENT OASyS DNA",
        "56015": "TELVENT OASyS DNA",
        "56016": "TELVENT OASyS DNA",
        "56017": "TELVENT OASyS DNA",
        "56018": "TELVENT OASyS DNA",
        "56019": "TELVENT OASyS DNA",
        "56020": "TELVENT OASyS DNA",
        "56021": "TELVENT OASyS DNA",
        "56022": "TELVENT OASyS DNA",
        "56023": "TELVENT OASyS DNA",
        "56024": "TELVENT OASyS DNA",
        "56025": "TELVENT OASyS DNA",
        "56026": "TELVENT OASyS DNA",
        "56027": "TELVENT OASyS DNA",
        "56028": "TELVENT OASyS DNA",
        "56029": "TELVENT OASyS DNA",
        "56030": "TELVENT OASyS DNA",
        "56031": "TELVENT OASyS DNA",
        "56032": "TELVENT OASyS DNA",
        "56033": "TELVENT OASyS DNA",
        "56034": "TELVENT OASyS DNA",
        "56035": "TELVENT OASyS DNA",
        "56036": "TELVENT OASyS DNA",
        "56037": "TELVENT OASyS DNA",
        "56038": "TELVENT OASyS DNA",
        "56039": "TELVENT OASyS DNA",
        "56040": "TELVENT OASyS DNA",
        "56041": "TELVENT OASyS DNA",
        "56042": "TELVENT OASyS DNA",
        "56043": "TELVENT OASyS DNA",
        "56044": "TELVENT OASyS DNA",
        "56045": "TELVENT OASyS DNA",
        "56046": "TELVENT OASyS DNA",
        "56047": "TELVENT OASyS DNA",
        "56048": "TELVENT OASyS DNA",
        "56049": "TELVENT OASyS DNA",
        "56050": "TELVENT OASyS DNA",
        "56051": "TELVENT OASyS DNA",
        "56052": "TELVENT OASyS DNA",
        "56053": "TELVENT OASyS DNA",
        "56054": "TELVENT OASyS DNA",
        "56055": "TELVENT OASyS DNA",
        "56056": "TELVENT OASyS DNA",
        "56057": "TELVENT OASyS DNA",
        "56058": "TELVENT OASyS DNA",
        "56059": "TELVENT OASyS DNA",
        "56060": "TELVENT OASyS DNA",
        "56061": "TELVENT OASyS DNA",
        "56062": "TELVENT OASyS DNA",
        "56063": "TELVENT OASyS DNA",
        "56064": "TELVENT OASyS DNA",
        "56065": "TELVENT OASyS DNA",
        "56066": "TELVENT OASyS DNA",
        "56067": "TELVENT OASyS DNA",
        "56068": "TELVENT OASyS DNA",
        "56069": "TELVENT OASyS DNA",
        "56070": "TELVENT OASyS DNA",
        "56071": "TELVENT OASyS DNA",
        "56072": "TELVENT OASyS DNA",
        "56073": "TELVENT OASyS DNA",
        "56074": "TELVENT OASyS DNA",
        "56075": "TELVENT OASyS DNA",
        "56076": "TELVENT OASyS DNA",
        "56077": "TELVENT OASyS DNA",
        "56078": "TELVENT OASyS DNA",
        "56079": "TELVENT OASyS DNA",
        "56080": "TELVENT OASyS DNA",
        "56081": "TELVENT OASyS DNA",
        "56082": "TELVENT OASyS DNA",
        "56083": "TELVENT OASyS DNA",
        "56084": "TELVENT OASyS DNA",
        "56085": "TELVENT OASyS DNA",
        "56086": "TELVENT OASyS DNA",
        "56087": "TELVENT OASyS DNA",
        "56088": "TELVENT OASyS DNA",
        "56089": "TELVENT OASyS DNA",
        "56090": "TELVENT OASyS DNA",
        "56091": "TELVENT OASyS DNA",
        "56092": "TELVENT OASyS DNA",
        "56093": "TELVENT OASyS DNA",
        "56094": "TELVENT OASyS DNA",
        "56095": "TELVENT OASyS DNA",
        "56096": "TELVENT OASyS DNA",
        "56097": "TELVENT OASyS DNA",
        "56098": "TELVENT OASyS DNA",
        "56099": "TELVENT OASyS DNA",


    }
    
    p1 = threading.Thread(target=srcmac, args=(packet_dict, i, es))
    p1.start()
    p2 = threading.Thread(target=dstmac, args=(packet_dict, i, es))
    p2.start()
    p3 = threading.Thread(target=dstvendor, args=(packet_dict, es))
    p3.start()
    p4 = threading.Thread(target=ip, args=(packet, packet_dict, es))
    p4.start()
    p5 = threading.Thread(target=srcvendor, args=(packet_dict, es))
    sp = srcport(packet_dict, packet, es)
    dp = dstport(packet_dict, packet, es)
    proto(packet_dict, packet, i, es, sp, dp, mapping)
    p1.join()
    p2.join()
    p3.join()
    p4.join()

    '''
    srcport(packet_dict,es)
    dstport(packet_dict,es)
    dstmac(packet_dict,i,es)
    srcmac(packet_dict,i,es)
    dstvendor(packet_dict,es)
    srcvendor(packet_dict,es)
    proto(packet_dict, packet,i,es)
    ip(packet, packet_dict,es)'''


def pcap(filename):
    ELASTIC_PASSWORD = "XQs+_IZI=JV7toA7PKrw"
    es = Elasticsearch("http://localhost:9200", http_auth=("elastic", ELASTIC_PASSWORD))
    es.options(ignore_status=[400, 404]).indices.delete(index='srcdst')
    es.options(ignore_status=[400, 404]).indices.delete(index='srcip')
    es.options(ignore_status=[400, 404]).indices.delete(index='dstip')
    es.options(ignore_status=[400, 404]).indices.delete(index='vendors')
    es.options(ignore_status=[400, 404]).indices.delete(index='protocol')
    es.options(ignore_status=[400, 404]).indices.delete(index='srcport')
    es.options(ignore_status=[400, 404]).indices.delete(index='dstport')
    es.options(ignore_status=[400, 404]).indices.delete(index='srcmac')
    es.options(ignore_status=[400, 404]).indices.delete(index='dstmac')
    packets = PcapReader(filename)
    # else:
    #    sys.exit()zzzzz

    delete()
    # createme()
    work(es, packets)
    export(es)
    networkgraph()


def createme():
    createfile("src-dst.csv")
    createfile("src-ip.csv")
    createfile("dst-ip.csv")
    createfile("vendor.csv")
    createfile("protocol.csv")
    createfile("src-port.csv")
    createfile("dst-port.csv")
    createfile("src-mac.csv")
    createfile("dst-mac.csv")


def createfile(file):
    with open(os.path.join("results", file), 'w') as fp:
        pass


def networkgraph():
    df = pd.read_csv('results/src-dst.csv')
    G = nx.from_pandas_edgelist(df, source='Source', target='Destination', edge_attr=True)
    # nx.draw(G, with_labels=True, node_color='lightblue', edge_color='grey')
    '''plt.savefig('static/images/network.png')
    html = mpld3.fig_to_html(plt.gcf())
    # print(html)
    with open('templates/network.html', 'w') as f:
        f.write(html)'''

    net = Network(
        notebook=True,
        cdn_resources="remote",
        bgcolor="#222222",
        height="1000px",
        width="100%",
        font_color="white")
    net.from_nx(G)

    net.write_html('templates/network.html')

    '''
    df = pd.read_csv('results/src-dst.csv')
    G = nx.from_pandas_edgelist( df, source='Source', target='Destination', edge_attr=True)
    net = Network(    
    notebook=True,
    cdn_resources="remote",
    bgcolor="#222222", 
    font_color="white",
    height="4000px",
    width="4000px",
)
    net.from_nx(G)
    net.show("templates/network-graph.html")'''


pcap_files = glob.glob("*.pcap")

# Loop through the files and delete them
for pcap_file in pcap_files:
    os.remove(pcap_file)
pcap_files = glob.glob("*.pcapng")

# Loop through the files and delete them
for pcap_file in pcap_files:
    os.remove(pcap_file)
app = Flask(__name__)


@app.route('/')
def upload():
    return render_template('upload.html')

# -------------------------------------------

@app.route('/network')
def graphtwo():
    return render_template('network.html')

# -------------------------------------------

def visualise(csvfile,title):
    labels = []
    values = []

    if os.path.isfile(csvfile):

        with open(csvfile, 'r') as csvf:

            lines = csv.reader(csvf, delimiter=',')
            for row in lines:
                # print(row)
                labels.append(row[0])
                values.append(int(row[1]))

    fig = go.Figure(data=[go.Pie(labels=labels, values=values, pull=[0.1, 0.1, 0.1, 0.1])])
    # fig = px.pie(values=values, names=labels)
    # fig.update_layout(showlegend=False)
    fig.update_layout(template='seaborn')
    fig.update_layout(title=title)
    h = pyo.plot(fig, include_plotlyjs=False, output_type='div')

    # graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    # chart_html = pyo.plot(fig,include_plotlyjs=False, output_type='div')
    # fig.write_html(img_static)
    # fig.write_html(img_static)
    # print(h)
    return h

# -------------------------------------------

@app.route('/work', methods=['POST', 'GET'])
def worktype():
    if request.method == 'POST':
        z = request.files['file']
        z.save(z.filename)
        dn = os.path.abspath(z.filename)
        webbrowser.open_new('http://127.0.0.1:5000/work')
        pcap(dn)
    time.sleep(7)
    a = visualise("results/protocol.csv","PROTOCOL")
    b = visualise("results/vendor.csv","VENDOR")
    c = visualise("results/src-ip.csv","SOURCE IP")
    d = visualise("results/dst-ip.csv","DESTINATION IP")
    e = visualise("results/src-port.csv","SOURCE PORT")
    f = visualise("results/dst-port.csv","DESTINATION PORT")
    g = visualise("results/src-mac.csv","SOURCE MAC")
    h = visualise("results/dst-mac.csv","DESTINATION MAC")
    return render_template('work.html', protocol=a, vendor=b, srcip=c, dstip=d,
                           srcport=e, dstport=f, srcmac=g,
                           dstmac=h)

app.run()
