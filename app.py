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
    abb = [ '10307', '10311', '10364' , '10365', '10407', '10409', '10410', '10412', '10414' , '10415', '10428', '10431', '10432', 
            '10447', '10449', '10450', '12316', '12645', '12647' , '12648', '13722', '13724', 
            '13782' , '13783', '38589', '38593', '38600', '38971', '39129', '39278']
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
        "34962": "PROFINET",
        "34963": "PROFINET",
        "34964": "PROFINET",
        "9600": "OMRON",
        "4000": "EMERSON FISHER",
        "55555": "FOXBORO FOXAPI",
        "45678": "FOXBORO AIMAPI",
        "1541": "FOXBORO INFORMIX",
        "18000": "ICONICS",
        "11001": "JOHNSON N1", 
        "10307": "ABB",
        "10311": "ABB",
        "10364": "ABB",
        "10365": "ABB",
        "10407": "ABB",
        "10409": "ABB",
        "10410": "ABB",
        "10412": "ABB",
        "10414": "ABB",
        "10415": "ABB",
        "10428": "ABB",
        "10431": "ABB",
        "10432": "ABB",
        "10447": "ABB",
        "10449": "ABB",
        "10450": "ABB",
        "12316": "ABB",
        "12645": "ABB",
        "12647": "ABB",
        "12648": "ABB",
        "13722": "ABB",
        "13724": "ABB",
        "13782": "ABB",
        "13783": "ABB",
        "38589": "ABB",
        "38593": "ABB",
        "38600": "ABB",
        "38971": "ABB",
        "39129": "ABB",
        "39278": "ABB",
        "5450": "OSISOFT",
        "50001": "SEIMENS",
        "50002": "SEIMENS",
        "50003": "SEIMENS",
        "50004": "SEIMENS",
        "50005": "SEIMENS",
        "50006": "SEIMENS",
        "50007": "SEIMENS",
        "50008": "SEIMENS",
        "50009": "SEIMENS",
        "50010": "SEIMENS",
        "50011": "SEIMENS",
        "50012": "SEIMENS",
        "50013": "SEIMENS",
        "50014": "SEIMENS",
        "50015": "SEIMENS",
        "50016": "SEIMENS",
        "50018": "SEIMENS",
        "50019": "SEIMENS",
        "50020": "SEIMENS",
        "50021": "SEIMENS",
        "50025": "SEIMENS",
        "50026": "SEIMENS",
        "50027": "SEIMENS",
        "50028": "SEIMENS",
        "50110": "SEIMENS",
        "50111": "SEIMENS",
        "38000": "SNC",
        "38001": "SNC",
        "38011": "SNC",
        "38012": "SNC",
        "38014": "SNC",
        "38015": "SNC",
        "38200": "SNC",
        "38210": "SNC",
        "38301": "SNC",
        "38400": "SNC",
        "38700": "SNC",
        "62900": "SNC",
        "62911": "SNC",
        "62924": "SNC",
        "62930": "SNC",
        "62938": "SNC",
        "62956": "SNC",
        "62957": "SNC",
        "62963": "SNC",
        "62981": "SNC",
        "62982": "SNC",
        "62985": "SNC",
        "62992": "SNC",
        "63012": "SNC",
        "63027": "SNC",
        "63028": "SNC",
        "63029": "SNC",
        "63030": "SNC",
        "63031": "SNC",
        "63032": "SNC",
        "63033": "SNC",
        "63034": "SNC",
        "63035": "SNC",
        "63036": "SNC",
        "63041": "SNC",
        "63075": "SNC",
        "63079": "SNC",
        "63082": "SNC",
        "63088": "SNC",
        "63094": "SNC",
        "65443": "SNC",
        "5050": "TELVENT",
        "5051": "TELVENT",
        "5052": "TELVENT",
        "5065": "TELVENT",
        "12135": "TELVENT",
        "12136": "TELVENT",
        "12137": "TELVENT",
        "56001": "TELVENT",
        "56002": "TELVENT",
        "56003": "TELVENT",
        "56004": "TELVENT",
        "56005": "TELVENT",
        "56006": "TELVENT",
        "56007": "TELVENT",
        "56008": "TELVENT",
        "56009": "TELVENT",
        "56010": "TELVENT",
        "56011": "TELVENT",
        "56012": "TELVENT",
        "56013": "TELVENT",
        "56014": "TELVENT",
        "56015": "TELVENT",
        "56016": "TELVENT",
        "56017": "TELVENT",
        "56018": "TELVENT",
        "56019": "TELVENT",
        "56020": "TELVENT",
        "56021": "TELVENT",
        "56022": "TELVENT",
        "56023": "TELVENT",
        "56024": "TELVENT",
        "56025": "TELVENT",
        "56026": "TELVENT",
        "56027": "TELVENT",
        "56028": "TELVENT",
        "56029": "TELVENT",
        "56030": "TELVENT",
        "56031": "TELVENT",
        "56032": "TELVENT",
        "56033": "TELVENT",
        "56034": "TELVENT",
        "56035": "TELVENT",
        "56036": "TELVENT",
        "56037": "TELVENT",
        "56038": "TELVENT",
        "56039": "TELVENT",
        "56040": "TELVENT",
        "56041": "TELVENT",
        "56042": "TELVENT",
        "56043": "TELVENT",
        "56044": "TELVENT",
        "56045": "TELVENT",
        "56046": "TELVENT",
        "56047": "TELVENT",
        "56048": "TELVENT",
        "56049": "TELVENT",
        "56050": "TELVENT",
        "56051": "TELVENT",
        "56052": "TELVENT",
        "56053": "TELVENT",
        "56054": "TELVENT",
        "56055": "TELVENT",
        "56056": "TELVENT",
        "56057": "TELVENT",
        "56058": "TELVENT",
        "56059": "TELVENT",
        "56060": "TELVENT",
        "56061": "TELVENT",
        "56062": "TELVENT",
        "56063": "TELVENT",
        "56064": "TELVENT",
        "56065": "TELVENT",
        "56066": "TELVENT",
        "56067": "TELVENT",
        "56068": "TELVENT",
        "56069": "TELVENT",
        "56070": "TELVENT",
        "56071": "TELVENT",
        "56072": "TELVENT",
        "56073": "TELVENT",
        "56074": "TELVENT",
        "56075": "TELVENT",
        "56076": "TELVENT",
        "56077": "TELVENT",
        "56078": "TELVENT",
        "56079": "TELVENT",
        "56080": "TELVENT",
        "56081": "TELVENT",
        "56082": "TELVENT",
        "56083": "TELVENT",
        "56084": "TELVENT",
        "56085": "TELVENT",
        "56086": "TELVENT",
        "56087": "TELVENT",
        "56088": "TELVENT",
        "56089": "TELVENT",
        "56090": "TELVENT",
        "56091": "TELVENT",
        "56092": "TELVENT",
        "56093": "TELVENT",
        "56094": "TELVENT",
        "56095": "TELVENT",
        "56096": "TELVENT",
        "56097": "TELVENT",
        "56098": "TELVENT",
        "56099": "TELVENT",


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
