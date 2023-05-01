from flask import Flask, render_template
from flask import request
import webbrowser
from elasticsearch import Elasticsearch  # SEARCHING
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
from scapy.utils import hexdump
import shutil
import binascii

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

        if test == "payload":
            b.append(impact["_id"])
            b.append(impact["_source"]["Payload"])

        else:
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


def proto(packet_dict, packet, i, es, sp, dp):
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
        ph = set(['TCP', 'UDP', 'LLC', 'STP', 'ARP', 'CIP', 'DNS'])
        z = set(y)
        g = ph.intersection(z)
        # print(g)
        try:
            a = list(g)[-1]
        except:
            pass
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
    elif 'DNS' in y or '|###[ DNS Question Record' in y:
        a = "DNS"
    
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

def payloadworks(packet,i):
    raw = bytes(packet.lastlayer())

    char_list = [chr(byte) if byte >= 32 and byte <= 126 else '.' for byte in raw]
    result = ''.join(char_list)
    result = "'" + str(result) + "'"
    d = [i, result]
    with open("results/payload.csv", mode='a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(d)

def work(es, packets):
    
    global i
    i = 1
    with open("results/payload.csv", mode='w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow('')

    for packet in packets:
        payloadworks(packet,i)

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
        
        #print(packet_dict)

        # ////////////////// MAIN FUNCTION ////////////////////////
        #print(list(packet_dict.keys()))

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
    proto(packet_dict, packet, i, es, sp, dp)
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
