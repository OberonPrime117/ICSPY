from multiprocessing import Pool
import os
import shutil
from flask import Flask, render_template, send_file, request
import webbrowser
from elasticsearch import Elasticsearch
import zipfile
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, rdpcap, PcapReader
import scapy.contrib.modbus as mb
import csv
import plotly.graph_objects as go
import plotly.offline as pyo
from scapy.all import *
from pyvis.network import Network
import pandas as pd
import threading
import glob
import networkx as nx
import json
import concurrent.futures
import requests
import sys
import re
from dotenv import dotenv_values

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

        #if test == "payload":
        #    b.append(impact["_id"])
        #    b.append(impact["_source"]["Payload"])

        #else:
        if test == "srcdst":
            trial = impact["_id"].split("--")
            b.append(trial[0]) 
            b.append(trial[1])  
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
    search("results/src-ip.csv", "srcip", es)
    search("results/dst-ip.csv", "dstip", es)
    search("results/vendor.csv", "vendors", es)
    search("results/protocol.csv", "protocol", es)
    search("results/src-port.csv", "srcport", es)
    search("results/dst-port.csv", "dstport", es)
    search("results/dst-mac.csv", "dstmac", es)
    search("results/src-mac.csv", "srcmac", es)
    search("results/src-dst.csv", "srcdst", es)

def esearch(es,esindex,esid,a):
    es.index(index=esindex, id=esid, body=a)

def ranking(esindex, esid, es, secondid=None):

    if secondid is None and esindex != "srcdst":
        try:
            resp = es.get(index=esindex, id=esid)
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index=esindex, id=esid, body=a)

        except Exception as e:
            a = {"Number of Packets": 1}
            resp = es.index(index=esindex, id=esid, body=a)

    elif esindex == "srcdst":
        eval = str(esid) + "--" + str(secondid)
        try:
            resp = es.get(index=esindex, id=eval)
            a = resp["_source"]
            a["Number of Packets"] = int(a["Number of Packets"]) + 1
            resp = es.index(index=esindex, id=eval, body=a)
        except:
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
    #iterate_deletecsv("results/payload.csv", )
    iterate_deletecsv("results/src-ip.csv", )
    iterate_deletecsv("results/dst-ip.csv", )
    iterate_deletecsv("results/src-port.csv", )
    iterate_deletecsv("results/dst-port.csv", )
    iterate_deletecsv("results/src-mac.csv", )
    iterate_deletecsv("results/dst-mac.csv", )
    iterate_deletecsv("results/protocol.csv", )
    iterate_deletecsv("results/vendor.csv", )
    iterate_deletecsv("results/src-dst.csv", )
    try:
        shutil.rmtree("results/packet")
    except Exception as e:
        pass


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
        all_keys = get_all_keys(packet_dict)
        for i in all_keys:
            if "src" in i:
                txt = i.split(".")[-1]
                a = get_value_by_key(packet_dict, txt)
    #print(a)
    ranking("srcmac", a, es)


def dstmac(packet_dict, i, es):
    h = list(packet_dict.keys())[0]

    try:
        a = packet_dict[h]["dst"]
    except:
        all_keys = get_all_keys(packet_dict)
        for i in all_keys:
            if "dst" in i or "dest" in i:
                txt = i.split(".")[-1]
                a = get_value_by_key(packet_dict, txt)
    
    #print(a)
    ranking("dstmac", a, es)

def proto(packet_dict, packet, i, es, sp, dp):
    
    if IP in packet_dict:
        a = proto_name_by_num(int(packet[IP].proto))  
    else:
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
        ph = set(['TCP', 'UDP', 'LLC', 'STP', 'ARP', 'CIP', 'DNS'])
        z = set(y)
        g = ph.intersection(z)
        try:
            a = list(g)[-1]
        except:
            pass

    for bh in y:
        if '.' in str(bh):
            d = bh.split(":")
            if 'ssdp' in d:
                a = "SSDP"
    if 'NBTSession' in y:
        a = "SAMBA"
        ranking("protocol", a, es)
        return a
    elif mb.ModbusADUResponse in packet:
        a = "ModbusTCP"
        ranking("protocol", a, es)
        return a
    elif 'DNS' in y or '|###[ DNS Question Record' in y:
        a = "DNS"
        ranking("protocol", a, es)
        return a
    elif "Ethernet" in y:
        if "0x88ab" == packet_dict["Ethernet"]["type"]:
            a = "POWERLINK"
            ranking("protocol", a, es)
            return a

    try:
        resp = es.get(index="elasticproto", id=sp)
        a = resp["_source"]["Protocol Name"]
    except:
        pass

    try:
        resp = es.get(index="elasticproto", id=dp)
        a = resp["_source"]["Protocol Name"]
    except:
        pass

    ranking("protocol", a, es)
    return a


def dstvendor(packet_dict, es):
    h = list(packet_dict.keys())[0]
    if "dst" in packet_dict[h] and packet_dict[h]["dst"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
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
                a = "N/A"
    
    if 'SNAP' in list(packet_dict.keys()):
        a = str(packet_dict['SNAP']['OUI']).split("(")[0]

    ranking("vendors", a, es)


def srcvendor(packet_dict, es):
    h = list(packet_dict.keys())[0]
    if "src" in packet_dict[h] and packet_dict[h]["src"] == 'ff:ff:ff:ff:ff:ff':
        a = "Broadcast"
    else:
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
                a = "N/A"

    ranking("vendors", a, es)


def srcport(packet_dict, packet, es):
    
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['sport']

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['sport']

    else:
        a = "N/A"

    ranking("srcport", a, es)
    return a


def dstport(packet_dict, packet, es):
    
    if 'UDP' in list(packet_dict.keys()):
        a = packet_dict["UDP"]['dport']

    elif 'TCP' in list(packet_dict.keys()):
        a = packet_dict["TCP"]['dport']

    else:
        a = "N/A"
    
    ranking("dstport", a, es)
    return a

def get_all_keys(dictionary):

    keys = []
    for key, value in dictionary.items():
        key.replace(" ","_")
        keys.append(key)
        if isinstance(value, dict):
            nested_keys = get_all_keys(value)
            for nested_key in nested_keys:
                keys.append(key + '.' + nested_key)
    return keys

def get_value_by_key(dictionary, target_key):
    for key, value in dictionary.items():
        if key == target_key:
            return value
        elif isinstance(value, dict):
            nested_value = get_value_by_key(value, target_key)
            if nested_value is not None:
                return nested_value
    return None

# 802154_Data.src_addr
def ip(packet, packet_dict, es):

    try:
        if IP in packet:
            a = str(packet["IP"].src)  
        else:
            try:
                a = packet_dict["8023"]["src"]  
            except:
                a = packet[Ether].src  
    except:
        try:
            a = packet_dict["8023"]["src"]  
        except:
            try:
                a = packet["Ethernet"].src 
            except:

                all_keys = get_all_keys(packet_dict)

                for i in all_keys:
                    if "src" in i:
                        #print(i)
                        txt = i.split(".")[-1]
                        a = get_value_by_key(packet_dict, txt)

    ranking("srcip", a, es)

    try:
        if IP in packet:
            b = str(packet["IP"].dst)  
        else:
            try:
                b = packet_dict["8023"]["dst"]  
            except:
                b = packet[Ether].dst  
    except:
        try:
            b = packet_dict["8023"]["dst"]  
        except:
            try:
                b = packet["Ethernet"].dst
            except:
                all_keys = get_all_keys(packet_dict)
                for i in all_keys:
                    if "dst" in i or "dest" in i:
                        #print(i)
                        txt = i.split(".")[-1]
                        b = get_value_by_key(packet_dict, txt)

    ranking("dstip", b, es)

    ranking("srcdst", a, es, b)

def payloadworks(packet,i):
    raw = bytes(packet.lastlayer())

    char_list = [chr(byte) if byte >= 32 and byte <= 126 else '.' for byte in raw]
    result = ''.join(char_list)
    result = "'" + str(result) + "'"
    d = [i, result]
    if not os.path.exists(os.path.join("results", "payload.csv")):
        with open(os.path.join("results", "payload.csv"), mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(d)
    else:
        with open(os.path.join("results", "payload.csv"), mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(d)

def work(es, packets):
    
    i = 1

    for packet in packets:

        packet_dict = {}
        data = {}
        heights = []
        data["Frame Number"] = str(i)
        new_dict = {}
        #print("COUNT - " + str(i))

        for line in packet.show2(dump=True).split('\n'):
            if '###' in line:
                layer = line.strip('#[] ')
                heights.append(layer)
                packet_dict[layer] = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                packet_dict[layer][key.strip()] = val.strip()
        
        new_dict = remove_special_chars(packet_dict)

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:

            # ////////////////// FUTURE EXECUTION //////////////////
            future = executor.submit(dash, packet, new_dict, i, es)

            #payloadworks(packet,i)

            # ////////////////// EXPORTING //////////////////
            if len(str(i)) <= 3:
                val = 10 ** int(len(str(i)))
                val = val / 2
                if i % val == 0:
                    export(es)
                    networkgraph()
            else:
                val = 10 ** int(len(str(i)))
                val = val / 5
                if i % val == 0:
                    export(es)
                    networkgraph()
            
            # ////////////////// WAITING FOR THREAD TO FINISH //////////////////
            res = future.result()
        
        
        i = i + 1
    return new_dict

def remove_special_chars(d):
    keys = list(d.keys())
    for k in keys:
        new_key = re.sub(r'[^\w\s]', '', k)
        if new_key != k:
            d[new_key] = d[k]
            del d[k]
            k = new_key

        if isinstance(d[new_key], dict):
            remove_special_chars(d[new_key])
            
            if new_key != k:
                d[new_key] = d[k]
                del d[k]
                
        elif isinstance(d[new_key], list):
            for item in d[new_key]:
                if isinstance(item, dict):
                    remove_special_chars(item)
                    
    return d


def dash(packet, packet_dict, i, es):

    sp = srcport(packet_dict,packet,es)
    dp = dstport(packet_dict,packet,es)
    dstmac(packet_dict,i,es)
    srcmac(packet_dict,i,es)
    dstvendor(packet_dict,es)
    srcvendor(packet_dict,es)
    protocol_used = proto(packet_dict, packet, i, es, sp, dp)
    ip(packet, packet_dict,es)

    # ////////////////// APPLICATION LAYER DATA EXPORT //////////////////
    folder_name = os.path.join("results", "packet")
    insider_folder = os.path.join("results", "packet", str(protocol_used))
    s = str(i) + ".json"
    total_folder = os.path.join("results", "packet", str(protocol_used) , str(s))

    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        if not os.path.exists(insider_folder):
            os.makedirs(insider_folder)
            with open(total_folder, 'w') as f:
                json.dump(packet_dict, f, indent=6)
        else:
            with open(total_folder, 'w') as f:
                json.dump(packet_dict, f, indent=6)
    else:
        if not os.path.exists(insider_folder):
            os.makedirs(insider_folder)
            with open(total_folder, 'w') as f:
                json.dump(packet_dict, f, indent=6)
        else:
            with open(total_folder, 'w') as f:
                json.dump(packet_dict, f, indent=6)

def pcap(filename):
    config = dotenv_values(".env") 
    AWS_ELASTIC_PASSWORD = config['AWS_ELASTIC_PASSWORD']
    AWS_EC2 = config['AWS_EC2']
    
    es = Elasticsearch(AWS_EC2, http_auth=("elastic", AWS_ELASTIC_PASSWORD),maxsize=25,verify_certs=False)
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

    delete()
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

    net = Network(
        notebook=True,
        cdn_resources="remote",
        bgcolor="#222222",
        height="1000px",
        width="100%",
        font_color="white")
    net.from_nx(G)

    net.write_html('templates/network.html')

pcap_files = glob.glob("*.pcap")
requests.packages.urllib3.disable_warnings()

for pcap_file in pcap_files:
    os.remove(pcap_file)
pcap_files = glob.glob("*.pcapng")

for pcap_file in pcap_files:
    os.remove(pcap_file)
app = Flask(__name__)
webbrowser.open_new('http://127.0.0.1:5000/')

@app.route('/')
def upload():
    return render_template('upload.html')

# -------------------------------------------

@app.route("/download")
def download_file():
    folder_name = "results"
    zip_filename = f"{folder_name}.zip"
    folder_path = os.path.join(os.getcwd(), folder_name)

    # Create the zip file
    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zip:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                zip.write(file_path, os.path.relpath(file_path, folder_path))

    return send_file(zip_filename, as_attachment=True)

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
    fig.update_layout(template='seaborn')
    fig.update_layout(title=title)
    h = pyo.plot(fig, include_plotlyjs=False, output_type='div')
    return h

# -------------------------------------------

@app.route('/dashboard', methods=['POST', 'GET'])
def worktype():
    if request.method == 'POST':
        z = request.files['file']
        z.save(z.filename)
        dn = os.path.abspath(z.filename)
        webbrowser.open_new('http://127.0.0.1:5000/dashboard')
        pcap(dn)

    if request.method == 'GET':

        a = visualise("results/protocol.csv","PROTOCOL")
        b = visualise("results/vendor.csv","VENDOR")
        c = visualise("results/src-ip.csv","SOURCE IP")
        d = visualise("results/dst-ip.csv","DESTINATION IP")
        e = visualise("results/src-port.csv","SOURCE PORT")
        f = visualise("results/dst-port.csv","DESTINATION PORT")
        g = visualise("results/src-mac.csv","SOURCE MAC")
        h = visualise("results/dst-mac.csv","DESTINATION MAC")
        return render_template('work.html', protocol=a, vendor=b, srcip=c, dstip=d,srcport=e, dstport=f, srcmac=g,dstmac=h)

app.run()
