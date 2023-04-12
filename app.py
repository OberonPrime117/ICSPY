import multiprocessing
from flask import Flask, render_template
import os 
from flask import request
from multiprocessing import Process
import webbrowser
import argparse
from elasticsearch import Elasticsearch # SEARCHING
import json
from dotenv import dotenv_values
import sys
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, rdpcap, PcapReader
import socket
import threading
import csv
import uuid
import plotly.graph_objects as go
from scapy.all import PcapReader
import networkx as nx
from pyvis.network import Network
import pandas as pd
from threading import Timer
import plotly.io as pio
from matplotlib import pyplot as plt


def visualise(img_static,csvfile):
    labels = []
    values = []

    if os.path.isfile(csvfile):

        with open(csvfile, 'r') as csvf:

            lines = csv.reader(csvf, delimiter = ',')
            for row in lines:
                labels.append(row[0])
                values.append(int(row[1]))

    fig = go.Figure(data=[go.Pie(labels=labels, values=values, pull=[0.1, 0.1, 0.2, 0.1])])
    fig.write_html(img_static)

def search(csvfile,test,es):

    searchp = { 
        "match_all" : {}
    }
    
    resp = es.search(index=test, query=searchp)

    for j in resp["hits"]["hits"]:
        impact = es.get(index=test,id=j["_id"])

        if test == "srcdst":
            with open(csvfile, mode='w', newline='') as f:
                b = ['Source','Destination','Number of Packets']
                writer = csv.writer(f)
                writer.writerow(b)
        b = []
        b.append(impact["_id"])
        if test == "srcdst":
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

def export_data(img_static,csvfile,test,es):
    search(csvfile,test,es)
    visualise(img_static,csvfile)

def export(es):
    export_data("templates/src-ip.html","results/src-ip.csv","srcip",es)
    export_data("templates/dst-ip.html","results/dst-ip.csv","dstip",es)
    export_data("templates/vendor.html","results/vendor.csv","vendors",es)
    export_data("templates/protocol.html","results/protocol.csv","protocol",es)
    export_data("templates/src-port.html","results/src-port.csv","srcport",es)
    export_data("templates/dst-port.html","results/dst-port.csv","dstport",es)
    export_data("templates/dst-mac.html","results/dst-mac.csv","dstmac",es)
    export_data("templates/src-mac.html","results/src-mac.csv","srcmac",es)
    search("results/src-dst.csv","srcdst",es)


def ranking(esindex,esid,es,secondid=None):
    try:
        resp = es.get(index=esindex,id=esid)
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        resp = es.index(index=esindex, id=esid, body=a)

    except:
        if secondid == None:
            dbody = {"Number of Packets" : 1}
        else:
            dbody = {"Number of Packets" : 1, "Destination IP": secondid}
        resp = es.index(index=esindex, id=esid, body=dbody)

def iterate_deletecsv(filename):
    try:
        os.remove(filename)
    except:
        pass

def delete():
    #config = dotenv_values(".env")
    #ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    #ELASTIC_PASSWORD = "XQs+_IZI=JV7toA7PKrw"
    #es =  Elasticsearch("http://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD))

    iterate_deletecsv("results/dst-ip.csv",)
    iterate_deletecsv("results/dst-port.csv",)
    iterate_deletecsv("results/protocol.csv",)
    iterate_deletecsv("results/src-ip.csv",)
    iterate_deletecsv("results/src-port.csv",)
    iterate_deletecsv("results/src-mac.csv",)
    iterate_deletecsv("results/dst-mac.csv",)
    iterate_deletecsv("results/vendor.csv",)
    iterate_deletecsv("results/src-dst.csv",)

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
                filename = "backup/data.json"
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
                filename = "backup/data.json"
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

def work(es, packets, i=1):

    for packet in packets:
        #print(i)

        packet_dict = {}
        data = {}
        heights = []
        data["Frame Number"] = str(i)

        print("COUNT - "+str(i))

        for line in packet.show2(dump=True).split('\n'):
            if '###' in line:
                layer = line.strip('#[] ')
                heights.append(layer)
                packet_dict[layer] = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                packet_dict[layer][key.strip()] = val.strip()

        # ////////////////// MAIN FUNCTION ////////////////////////
        #print(list(packet_dict.keys()))

        dash(packet,packet_dict,i,es)
        #rankme(es,data)

        if len(str(i)) <= 3:
            val = 10**int(len(str(i)))
            val = val/2
            if i%val==0:
                export(es)
                networkgraph()

            # 3 digits - 100 , 400 45455
        else:
            # 5000 , 10,000
            val = 10**int(len(str(i)))
            val = val/5
            if i%val==0:
                export(es)
                networkgraph()

        i = i + 1


def dash(packet,packet_dict,i,es):
    srcport(packet_dict,es)
    dstport(packet_dict,es)
    dstmac(packet_dict,i,es)
    srcmac(packet_dict,i,es)
    dstvendor(packet_dict,es)
    srcvendor(packet_dict,es)
    proto(packet_dict, packet,i,es)
    ip(packet, packet_dict,es)

def pcap(filename):
    #parser = argparse.ArgumentParser()
    #parser.add_argument("-p", "--pcap", help = "Enter your pcap file")
    #args = parser.parse_args()
    #if args.pcap:
    #config = dotenv_values(".env")
    #ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    ELASTIC_PASSWORD = "XQs+_IZI=JV7toA7PKrw"
    es =  Elasticsearch("http://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD))
    packets = PcapReader(filename)
    #else:
    #    sys.exit()

    p1 = multiprocessing.Process(target=delete())
    p1.start()
    

    p2 = multiprocessing.Process(target=work(es,packets))
    p2.start()
    p1.join()
    p2.join()
    print("Done!")
    es.options(ignore_status=[400,404]).indices.delete(index='srcdst')
    es.options(ignore_status=[400,404]).indices.delete(index='srcip')
    es.options(ignore_status=[400,404]).indices.delete(index='dstip')
    es.options(ignore_status=[400,404]).indices.delete(index='vendors')
    es.options(ignore_status=[400,404]).indices.delete(index='protocol')
    es.options(ignore_status=[400,404]).indices.delete(index='srcport')
    es.options(ignore_status=[400,404]).indices.delete(index='dstport')

app = Flask(__name__)

@app.route('/')
def upload():
    return render_template('upload.html')

@app.route('/pcap/protocol')
def protocolexp():
    return render_template('protocol.html')

# -------------------------------------------

@app.route('/pcap/ip')
def ipexp():
    return render_template('ip.html')

@app.route('/pcap/ip/dst')
def dstipexp():
    return render_template('dst-ip.html')

@app.route('/pcap/ip/src')
def srcipexp():
    return render_template('src-ip.html')

# -------------------------------------------

# -------------------------------------------

@app.route('/pcap/mac')
def macexp():
    return render_template('mac.html')

@app.route('/pcap/mac/src')
def srcmacexp():
    return render_template('src-mac.html')

@app.route('/pcap/mac/dst')
def dstmacexp():
    return render_template('dst-mac.html')

# -------------------------------------------

@app.route('/pcap/vendor')
def vendorexp():
    return render_template('vendor.html')

# -------------------------------------------

@app.route('/pcap/port')
def portexp():
    return render_template('port.html')

@app.route('/pcap/port/src')
def srcportexp():
    return render_template('src-port.html')

@app.route('/pcap/port/dst')
def dstportexp():
    return render_template('dst-port.html')

# -------------------------------------------

@app.route('/success', methods = ['POST','GET'])
def success():
    
    return render_template('success.html')

@app.route('/pcap', methods = ['POST','GET'])
def capture():
    if request.method == 'POST':  
        f = request.files['file']
        f.save(f.filename)
        dn = os.path.abspath(f.filename)
        #print(dn)
        webbrowser.open_new("http://127.0.0.1:5000/pcap")
        pcap(dn)
        os.remove(f.filename)
    sip = 'src-ip.html'
    dip = 'dst-ip.html'
    vendor = 'vendor.html'
    protocol = 'protocol.html'
    sport = 'src-port.html'
    dport = 'dst-port.html'
    smac = 'src-mac.html'
    dmac = 'dst-mac.html'
    
    return render_template('home.html',sip=sip, dip=dip,vendor=vendor,protocol=protocol, sport=sport,dport=dport,smac=smac,dmac=dmac)

def networkgraph():
    df = pd.read_csv('results/src-dst.csv')
    G = nx.from_pandas_edgelist( df, source='Source', target='Destination', edge_attr=True)
    net = Network(notebook=True)
    net.from_nx(G)
    net.show("templates/network-graph.html")

@app.route('/network-graph')
def graph():
    return render_template('network-graph.html')

app.run()
