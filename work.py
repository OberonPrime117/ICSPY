import sys
import time
import multiprocessing
from dash import dash
from functions.rank import *
from functions.export import export
import argparse
from scapy.all import PcapReader
import os

def work(packets, i=1):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

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
                os.system("python networkgraph.py")

            # 3 digits - 100 , 400 45455
        else:
            # 5000 , 10,000
            val = 10**int(len(str(i)))
            val = val/5
            if i%val==0:
                export(es)
                os.system("python networkgraph.py")

        i = i + 1