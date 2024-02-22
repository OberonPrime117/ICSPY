from threading import Timer
import time
import pandas as pd
import networkx as nx
from pyvis.network import Network
import os
import shutil
from flask import request
import webbrowser
from elasticsearch import Elasticsearch
import scapy.contrib.modbus as mb
from scapy.all import IP, PcapReader, Ether
import re
from concurrent.futures import ThreadPoolExecutor
import json
import csv
import requests
import glob

def increment_val(id, data, srcdst=None):

    if srcdst is None:
        if id in data:
            data[id] += 1
        else:
            data[id] = 1
    else:
        key = str(id) + "___" + str(srcdst)
        if key in data:
            data[key] += 1
        else:
            data[key] = 1

    return data

def datatocsv(csvfile, key, srcdst=None):

    # CSV FILE IN RESULTS DIRECTORY
    csvfile = os.path.join("results", csvfile)

    # NO SRCDST (ONLY 2 COLUMNS - VALUE AND COUNT)
    if srcdst is None:

        data = {}

        # READ CSV FILE
        if os.path.exists(csvfile):
            with open(csvfile) as f:
                reader = csv.reader(f)
                for row in reader:
                    id, count = row
                    data[id] = int(count)
        
        # INCREMENT COUNT
        data = increment_val(key, data)

        # WRITE INTO CSV FILE
        with open(csvfile, 'w') as f:
            writer = csv.writer(f)
            for id, count in data.items():
                writer.writerow([id, count])

    # SRCDST (ONLY 3 COLUMNS - VALUE_A, VALUE_B AND COUNT)
    else:

        data = {}

        # READ CSV FILE
        if os.path.exists(csvfile):
            with open(csvfile) as f:
                reader = csv.reader(f)
                for row in reader:
                    src, dst, count = row
                    key = str(src) + "___" + str(dst)
                    try:
                        data[key] = int(count)
                    except:
                        pass

        # INCREMENT COUNT
        data = increment_val(key, data, srcdst)

        # WRITE INTO CSV FILE
        with open(csvfile, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(["Source", "Destination", "Number of Packets"])
            for id, count in data.items():
                storeval = id.split("___")
                writer.writerow([storeval[0], storeval[1], count])


def ip_addr(packet, packet_dict):

    # SOURCE

    try:
        # FINDING IP
        if IP in packet:
            # IP SRC
            a = str(packet["IP"].src)
        else:
            try:
                # 802.3 SRC
                a = packet_dict["8023"]["src"]
            except:
                # ETHER SRC
                a = packet[Ether].src
    except:
        try:
            # 802.3 SRC
            a = packet_dict["8023"]["src"]
        except:
            try:
                # ETHERNET SRC
                a = packet["Ethernet"].src
            except:
                all_keys = get_all_keys(packet_dict)

                for i in all_keys:
                    if "src" in i:
                        txt = i.split(".")[-1]
                        a = get_value_by_key(packet_dict, txt)

    # STORE INTO CSV
    datatocsv("src-ip.csv", a)

    # DESTINATION

    try:
        # FINDING IP
        if IP in packet:
            # IP DST
            b = str(packet["IP"].dst)
        else:
            try:
                # 802.3 DST
                b = packet_dict["8023"]["dst"]
            except:
                # ETHERNET DST
                b = packet[Ether].dst
    except:
        try:
            # 802.3 DST
            b = packet_dict["8023"]["dst"]
        except:
            try:
                # ETHERNET DST
                b = packet["Ethernet"].dst
            except:
                all_keys = get_all_keys(packet_dict)

                for i in all_keys:
                    if "dst" in i or "dest" in i:
                        txt = i.split(".")[-1]
                        b = get_value_by_key(packet_dict, txt)

    # STORE INTO CSV
    datatocsv("dst-ip.csv", b)

    # STORE INTO CSV
    datatocsv("src-dst.csv", a, b)


def proto(packet_dict, packet, es, sp, dp):

    flag = 0
    y = packet.summary().split()
    for b in y:
        if b.isupper():
            final_protocol = b
            flag = 1
            continue
        elif flag == 0:
            final_protocol = "Other"

    if "(" in str(final_protocol) or ")" in str(final_protocol):
        final_protocol = final_protocol[1:]
        final_protocol = final_protocol[:-1]

    if len(final_protocol) < 3:
        ph = set(['TCP', 'UDP', 'ICMP', 'LLC', 'STP', 'ARP', 'CIP', 'DNS'])
        z = set(y)
        print(z)
        g = ph.intersection(z)
        try:
            final_protocol = list(g)[-1]
        except:
            pass

    val_dict = list(packet_dict.keys())
    mydict = [i.strip() for i in val_dict]
    total_keys = []

    for j in mydict:
        k = j.split(" ")
        total_keys.extend(k)

    total_keys = list(set(total_keys))

    # SPECIAL CASES FOR SSDP
    y = set(packet.summary().split())

    # FIND PROTOCOL IN KEYS OF PACKET_DICT
    protocol_list = ["CIP", "ICMP",
                     "(LOOP)", "DNS", "STP", "ARP", "LLC", "UDP", "TCP"]

    # FINAL PROTOCOL - SIMPLE PROTOCOL
    for found in protocol_list:
        if found in total_keys:
            if "(LOOP)" == found:
                final_protocol = "LOOP"
            else:
                final_protocol = found
            break

    # SPECIAL CASES FOR SSDP
    for bh in y:
        if '.' in str(bh):
            d = bh.split(":")
            if 'ssdp' in d:
                final_protocol = "SSDP"

    # SPECIAL CASES
    if 'NBTSession' in y:
        final_protocol = "SAMBA"
        datatocsv("protocol.csv", final_protocol)
        return final_protocol

    elif mb.ModbusADUResponse in packet:
        final_protocol = "ModbusTCP"
        datatocsv("protocol.csv", final_protocol)
        return final_protocol

    elif "Ethernet" in y:
        if "0x88ab" == packet_dict["Ethernet"]["type"]:
            final_protocol = "POWERLINK"
            datatocsv("protocol.csv", final_protocol)
            return final_protocol

    # ELASTICPROTO EXTRACT PROTOCOL VIA PORT
    try:
        resp = es.get(doc_type="_doc", index="elasticproto", id=sp)
        final_protocol = resp["_source"]["Protocol Name"]
    except:
        pass

    # ELASTICPROTO EXTRACT PROTOCOL VIA PORT
    try:
        resp = es.get(doc_type="_doc", index="elasticproto", id=dp)
        final_protocol = resp["_source"]["Protocol Name"]
    except:
        pass

    # PROTOCOL VIA PORT
    if "bacnet" == sp or "bacnet" == dp:
        final_protocol = "BACnet"
    elif "dnp" == sp or "dnp" == dp:
        final_protocol = "DNP3"
    elif "mbap" == sp or "mbap" == dp:
        final_protocol = "MODBUS"

    # RETURN FINDING FOR PROTOCOL
    datatocsv("protocol.csv", final_protocol)

    return final_protocol


def srcvendor(packet_dict, es):

    # EXTRACT KEYS FROM PACKET DICT
    h = list(packet_dict.keys())[0]

    # BROADCAST
    if "src" in packet_dict[h] and packet_dict[h]["src"] == 'ff:ff:ff:ff:ff:ff':
        final_sv = "Broadcast"
    else:
        # EXTRACT SRC FROM PACKET_DICT
        try:
            ab = packet_dict[h]["src"]
            val = str(ab).upper()
            resp = es.get(doc_type="_doc", index="mac-vendors", id=val)
            final_sv = resp['_source']["Vendor Name"]
        except:
            try:
                ab = packet_dict[h]["src"]
                val = str(ab)[0:8].upper()
                resp = es.get(doc_type="_doc", index="mac-vendors", id=val)
                final_sv = resp['_source']["Vendor Name"]
            except:
                final_sv = "N/A"

    # CAPITALISE FINDING
    final_sv = final_sv.upper()

    # RETURN FINDING FOR PROTOCOL
    datatocsv("vendor.csv", final_sv)


def dstvendor(packet_dict, es):

    # EXTRACT KEYS FROM PACKET DICT
    h = list(packet_dict.keys())[0]

    # BROADCAST
    if "dst" in packet_dict[h] and packet_dict[h]["dst"] == 'ff:ff:ff:ff:ff:ff':
        final_dv = "Broadcast"
    else:
        # EXTRACT DST FROM PACKET_DICT
        try:
            ab = packet_dict[h]["dst"]
            val = str(ab).upper()
            resp = es.get(doc_type="_doc", index="mac-vendors", id=val)
            final_dv = resp['_source']["Vendor Name"]
        except:
            try:
                ab = packet_dict[h]["dst"]
                val = str(ab)[0:8].upper()
                resp = es.get(doc_type="_doc", index="mac-vendors", id=val)
                final_dv = resp['_source']["Vendor Name"]
            except:
                final_dv = "N/A"

    # SPECIAL CASE FOR SNAP
    if 'SNAP' in list(packet_dict.keys()):
        final_dv = str(packet_dict['SNAP']['OUI']).split("(")[0]

    # CAPITALISE FINDING
    final_dv = final_dv.upper()

    # RETURN FINDING FOR PROTOCOL
    datatocsv("vendor.csv", final_dv)


def get_all_keys(dictionary):

    keys = []
    for key, value in dictionary.items():
        key.replace(" ", "_")
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


def srcmac(packet_dict):

    # EXTRACT KEYS FROM PACKET DICT
    h = list(packet_dict.keys())[0]

    # FIND MAC ADDRESS
    try:
        final_sm = packet_dict[h]["src"]
    except:
        all_keys = get_all_keys(packet_dict)
        for i in all_keys:
            if "src" in i:
                txt = i.split(".")[-1]
                final_sm = get_value_by_key(packet_dict, txt)

    # RETURN FINDING FOR PROTOCOL
    datatocsv("src-mac.csv", final_sm)


def dstmac(packet_dict):

    # EXTRACT KEYS FROM PACKET DICT
    h = list(packet_dict.keys())[0]

    # FIND MAC ADDRESS
    try:
        final_dm = packet_dict[h]["dst"]
    except:
        all_keys = get_all_keys(packet_dict)
        for i in all_keys:
            if "dst" in i or "dest" in i:
                txt = i.split(".")[-1]
                final_dm = get_value_by_key(packet_dict, txt)

    # RETURN FINDING FOR PROTOCOL
    datatocsv("dst-mac.csv", final_dm)


def srcport(packet_dict):

    # UDP TCP SRC PORT
    if 'UDP' in list(packet_dict.keys()):
        final_sp = packet_dict["UDP"]['sport']
    elif 'TCP' in list(packet_dict.keys()):
        final_sp = packet_dict["TCP"]['sport']
    else:
        final_sp = "N/A"

    # WRITE DATA TO CSV
    datatocsv("src-port.csv", final_sp)

    # RETURN FINDING FOR PROTOCOL
    return final_sp


def dstport(packet_dict):

    # UDP TCP DST PORT
    if 'UDP' in list(packet_dict.keys()):
        final_dp = packet_dict["UDP"]['dport']
    elif 'TCP' in list(packet_dict.keys()):
        final_dp = packet_dict["TCP"]['dport']
    else:
        final_dp = "N/A"

    # WRITE DATA TO CSV
    datatocsv("dst-port.csv", final_dp)

    # RETURN FINDING FOR PROTOCOL
    return final_dp


def networkgraph():

    # READ CSV
    df = pd.read_csv('results/src-dst.csv')

    # NETWORKX
    G = nx.from_pandas_edgelist(
        df, source='Source', target='Destination', edge_attr=True)

    # NETWORKX CONFIGURATION
    net = Network(
        notebook=True,
        cdn_resources="remote",
        bgcolor="#222222",
        height="1000px",
        width="100%",
        font_color="white")

    # FROM NETWORKX
    net.from_nx(G)

    # WRITE NETWORK HTML
    net.write_html('templates/network.html')


def dash(packet, packet_dict, i, es):

    # CALLING FUNCTIONS
    sp = srcport(packet_dict)
    dp = dstport(packet_dict)
    dstmac(packet_dict)
    srcmac(packet_dict)
    dstvendor(packet_dict, es)
    srcvendor(packet_dict, es)
    protocol_used = proto(packet_dict, packet, es, sp, dp)
    ip_addr(packet, packet_dict)

    # VARIABLE FOLDER CREATION
    folder_name = os.path.join("results", "packet")
    insider_folder = os.path.join("results", "packet", str(protocol_used))
    s = str(i) + ".json"
    total_folder = os.path.join(
        "results", "packet", str(protocol_used), str(s))

    # DUMP PACKET DETAILS
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


def work(es, packets, i=1):

    for packet in packets:

        # INITIALIZATION
        packet_dict = {}
        heights = []
        new_dict = {}

        # PACKET SHOW DETAILS
        for line in packet.show2(dump=True).split('\n'):
            if '###' in line:
                layer = line.strip('#[] ')
                heights.append(layer)
                packet_dict[layer] = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                packet_dict[layer][key.strip()] = val.strip()

        # REMOVE SPECIAL CHARACTERS FROM DETAILS
        new_dict = remove_special_chars(packet_dict)

        with ThreadPoolExecutor(max_workers=50) as executor:

            # SUBMIT THREAD
            future = executor.submit(dash, packet, new_dict, i, es)

            # NETWORK GRAPH PROCESSING
            if len(str(i)) <= 3:
                val = 10 ** int(len(str(i)))
                val = val / 2
                if i % val == 0:
                    networkgraph()
            else:
                val = 10 ** int(len(str(i)))
                val = val / 5
                if i % val == 0:
                    networkgraph()

            # WAITING FOR THREAD TO FINISH
            res = future.result()

        # INCREMENT COUNT
        i = i + 1


def pcap(filename):

    # BONSAI URL
    aws_ec2 = "https://saflu608fd:hn4wq7ssu4@testing-6258629515.us-east-1.bonsaisearch.net:443"

    # ELASTICSEARCH PYTHON
    es = Elasticsearch(aws_ec2, verify_certs=False)

    # PCAP READER
    packets = PcapReader(filename)

    # PACKET EXTRACTION
    work(es, packets)

    # FINAL PROCESSING FOR NETWORK GRAPH
    networkgraph()


def iterate_deletecsv(filename):

    if os.path.exists(filename):
        os.remove(filename)


def delete_csv():

    

    list_of_files = ["results/src-ip.csv", "results/dst-ip.csv", "results/src-port.csv", "results/dst-port.csv",
                     "results/src-mac.csv", "results/dst-mac.csv", "results/protocol.csv", "results/vendor.csv", "results/src-dst.csv"]

    for file_loc in list_of_files:
        loc = file_loc.split("/")
        updated_loc = os.path.join(loc[0], loc[1])
        iterate_deletecsv(updated_loc)

    try:
        # DELETE "PACKET" DIRECTORY
        shutil.rmtree("results/packet")
    except Exception as e:
        pass

if __name__ == "__main__":

    # DELETE CSV IF THEY EXIST
    delete_csv()
    
    requests.packages.urllib3.disable_warnings()
    
    webbrowser.open("http://127.0.0.1:5000/dashboard", new=2)

    # CREATE RESULTS FOLDER IF IT DOES NOT EXISTS
    if not os.path.exists("results"):
        os.makedirs(os.path.join("results"))
    
    # EXTRACT FILE UPLOADED BY USER
    pcap_files = glob.glob("*.pcap")
    if len(pcap_files) == 0:
        pcap_files = glob.glob("*.pcapng")
    
    for pcap_file in pcap_files:
        pcap(pcap_file)            
