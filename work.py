import sys
import time
import multiprocessing
from dash import dash
from functions.rank import *
from functions.export import export

def work(es,packets,i=1):
    for packet in packets:

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
        print(packet_dict)

        data = dash(packet,data,packet_dict,i,es)
        rankme(es,data)

        if i > 200 and i%200==0 and i != 0:
            export(es)

        i = i + 1