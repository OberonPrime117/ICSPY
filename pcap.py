import json
import pprint
import requests
from OuiLookup import OuiLookup
from tabulate import tabulate
from scapy.all import *
from scapy.layers.l2 import getmacbyip, Ether
import pandas as pd
import binascii
import matplotlib.pyplot as plt
from tkinter import filedialog as fd
import urllib.request as urllib2
import json
import codecs
from scapy.layers.inet import IP
from mac_vendor_lookup import MacLookup
from scapy.layers.inet import TCP, UDP
def select_file():
    filetypes = (
        ('PCAP', '*.pcap'),
        ('PCAPNG', '*.pcapng'),
        ('All files', '*.*')
    )

    filename = fd.askopenfilename(
        title='Open a file',
        initialdir='/',
        filetypes=filetypes)

    return filename

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def main():
    filep = select_file()
    #packets = rdpcap("file2.pcap")
    packets = rdpcap(filep)

    i=1
    data = {}
    final = {}
    ip_new = {}
    newance = []
    mac_src = []
    mac_dst = []
    tcpportlist = {}
    udpportlist = {}
    packet_dict = {}
    protocol = {"BACnet":[47808], "DNP3": [20000,20000], "EtherCAT": [34980], "Ethernet/IP" : [44818,2222,44818],
                "FL-net" : [55000 , 55001 ,55002 ,55003 ] , "Foundation Fieldbus HSE": [1089 ,1090 ,1091, 1089  ], "ICCP":[102], "Modbus TCP":[502],
                "OPC UA Discovery Server" : [4840], "OPC UA XML": [80,443], "PROFINET": [34962 ,34963 ,34964],"ROC Plus" : [4000]}

    #keys_to_remove = {"802.3"}

    transfer = []
    transfer2 = []
    mac_src = ""
    mac_dst = ""

    print("/////////// LOADING ////////////")
    for packet in packets:

        # /////////////////////////////////////////////////////////////////////////////////
        # ADDITIONAL INFORMATION INSIDE DATA.JSON 

        length = len(packet)
        for line in packet.show2(dump=True).split('\n'):
            if '###' in line:
                layer = line.strip('#[] ')
                packet_dict[layer] = {}
            elif '=' in line:
                key, val = line.split('=', 1)
                packet_dict[layer][key.strip()] = val.strip()

        # /////////////////////////////////////////////////////////////////////////////////
        # RESET VALUES 

        ip_src = ""
        ip_dst = ""
        proto_name = ""
        mac_src = ""
        mac_dst = ""
        route = ""
        mac_vendor_src = []
        mac_vendor_dst = []
        temp = []
        temp.append(str(i))

        # /////////////////////////////////////////////////////////////////////////////////
        # SRC & DST IP ADDRESS & PROTOCOL 

        if IP in packet:
            route = route + "1"
            ip_src=str(packet[IP].src)
            ip_dst=str(packet[IP].dst)
            proto_name = proto_name_by_num(int(packet[IP].proto))

        # /////////////////////////////////////////////////////////////////////////////////
        # DATA 

        data[str(i)] = {'Frame Number': str(i),
            'Protocol': proto_name, 'Source IP': str(ip_src), 'Destination IP': str(ip_dst),
            'Frame Length': str(length) , 'Additional Information': packet_dict}

        # /////////////////////////////////////////////////////////////////////////////////
        # ETHER & 802.3

        if str(data[str(i)]["Source IP"]) == "":
            route = route + "5"
            try:
                route = route + "6"
                data[str(i)]["Source IP"] = packet[Ether].src
            except:
                route = route + "7"
                data[str(i)]["Source IP"] = packet_dict["802.3"]["src"]
        if str(data[str(i)]["Destination IP"]) == "":
            route = route + "8"
            try:
                route = route + "9"
                data[str(i)]["Destination IP"] = packet[Ether].dst
            except:
                route = route + "A"
                data[str(i)]["Destination IP"] = packet_dict["802.3"]["dst"]

        # /////////////////////////////////////////////////////////////////////////////////
        # APPEND SRC & DST IP ADDRESS 

        temp.append(data[str(i)]['Source IP'])
        temp.append(data[str(i)]['Destination IP'])

        # /////////////////////////////////////////////////////////////////////////////////
        # IF IP ADDRESS HAS LESS THAN 5 NUMBER

        if len(str(data[str(i)]["Source IP"])) <= 5 or len(str(data[str(i)]["Source IP"])) <= 5 :
            print((data[str(i)]["Source IP"], data[str(i)]["Destination IP"]),end="\t")
            print(str(i),end="\t")
            print(route)
            if os.path.exists("route.txt"):
                pass
            else:
                with open('route.txt', 'w') as f:
                    f.write("")
                    f.close()

            if os.stat("route.txt").st_size == 0:
                with open('route.txt', 'w') as f:
                    f.write(route+"\t"+str(i)+"\t"+str(data[str(i)]["Source IP"]) +"\t" +str(data[str(i)]["Destination IP"])+"\n")
                    f.close()
            else:
                with open('route.txt', 'a') as f:
                    f.write(route+"\t"+str(i)+"\t"+str(data[str(i)]["Source IP"]) +"\t"+str(data[str(i)]["Destination IP"])+"\n")
                    f.close()
            
        # /////////////////////////////////////////////////////////////////////////////////
        # MAC ADDRESS OF PACKET = mac_src  mac_dst
        try:
            mac_src = getmacbyip(str(data[str(i)]["Source IP"]))
        except:
            try:
                #data[str(i)]["Source IP"] = packet[Ether].src
                mac_src = packet[Ether].src
            except:
                mac_src = data[str(i)]["Additional Information"]["802.3"]["src"]

        try:
            mac_dst = getmacbyip(str(data[str(i)]["Destination IP"]))
        except:
            try:
                #data[str(i)]["Destination IP"] = packet[Ether].dst
                mac_dst = packet[Ether].dst
            except:
                mac_dst = data[str(i)]["Additional Information"]["802.3"]["dst"]
        

        # /////////////////////////////////////////////////////////////////////////////////
        # IP OCCURENCE IP_NEW

        if (data[str(i)]["Source IP"], data[str(i)]["Destination IP"]) in list(ip_new.keys()):
            ip_new[(data[str(i)]["Source IP"], data[str(i)]["Destination IP"])] = ip_new[(data[str(i)]["Source IP"], data[str(i)]["Destination IP"])] + 1
        else:
            ip_new[(data[str(i)]["Source IP"], data[str(i)]["Destination IP"])] = 1
        
        ip_new = dict(sorted(ip_new.items(),key=lambda item: item[1], reverse=True))

        # /////////////////////////////////////////////////////////////////////////////////
        # IP OCCURENCE

        if "::" in str(data[str(i)]["Source IP"]) and "::" in str(data[str(i)]["Destination IP"]):
            mac1 = str(packet[Ether].src)
            mac21 = str(packet[Ether].dst)
        else:
            try:
                mac_src = getmacbyip(str(data[str(i)]["Source IP"]))
            except:
                try:
                    #data[str(i)]["Source IP"] = packet[Ether].src
                    mac_src = packet[Ether].src
                except:
                    mac_src = data[str(i)]["Additional Information"]["802.3"]["src"]

            try:
                mac_dst = getmacbyip(str(data[str(i)]["Destination IP"]))
            except:
                try:
                    #data[str(i)]["Destination IP"] = packet[Ether].dst
                    mac_dst = packet[Ether].dst
                except:
                    mac_dst = data[str(i)]["Additional Information"]["802.3"]["dst"]

        
        # /////////////////////////////////////////////////////////////////////////////////
        # OUILOOKUP QUERY 

        try:
            if mac_dst == 'ff:ff:ff:ff:ff:ff':
                mac_dst = "Broadcast"
                temp.append(mac_dst)
            else:
                mac_vendor_src = OuiLookup().query(mac_dst)
                temp.append(list(mac_vendor_src[0].items())[0][1])
        except:
            temp.append("None")

        try:
            if mac_src == 'ff:ff:ff:ff:ff:ff':
                mac_src = "Broadcast"
                temp.append(mac_src)
            else:
                mac_vendor_dst = OuiLookup().query(mac21)
                temp.append(list(mac_vendor_dst[0].items())[0][1])
        except:
            temp.append("None")

        # /////////////////////////////////////////////////////////////////////////////////
        # FOR THE NEXT LOOP

        i = i + 1
        transfer.append(temp)

    # /////////////////////////////////////////////////////////////////////////////////
    # EXPORT DATA.JSON 

    with open('data.json', 'w') as f:
        json.dump(data, f,indent=4)

    print("/////////// JSON EXPORT DONE ////////////")

    print("/////////// PAYLOAD CHECK ////////////")

    # /////////////////////////////////////////////////////////////////////////////////
    # EXPORT DATA.JSON 

    i=int(0)
    for key in ip_new.keys():
        if i<10:
            newance = []
            newance.append(key[0])
            newance.append(key[1])
            newance.append(ip_new[key])
            transfer2.append(newance)
        i = i+1


    tabling = tabulate(transfer, headers=["Frame Number","Src IP Address", "Dst IP Address", "Vendor Device Src", "Vendor Device Dst"])
    tabling2 = tabulate(transfer2, headers=["Src IP Address", "Dst IP Address", "Number of Packets Shared"])


    print("/////////// PAYLOAD CHECK DONE ////////////")
    print("/////////// COMPILING REPORT ////////////")

    with open('report.txt', 'w') as f:
        f.write("Top 10 IP Addresses which exchange packets : \n\n")
        f.write(tabling2)
    with open('report.txt', 'a') as f:
        f.write("\n\n\nVendor Name Derived from Payload : \n\n")
        f.write(tabling)

if __name__ == "__main__":
    main()