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

filep = select_file()
packets = rdpcap(filep)

i=0
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



print("/////////// LOADING ////////////")
for packet in packets:
    length = len(packet)
    i += 1
    x = str(packet.summary()).split(" ")
    for line in packet.show2(dump=True).split('\n'):
        if '###' in line:
            layer = line.strip('#[] ')
            packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            packet_dict[layer][key.strip()] = val.strip()
    #print(conf.ifaces)
    
        #print("YO")


    if x[5] == '115':
        data[str(i)] = {'Frame Number': str(i),
        'Protocol': "L2TP", 'Source IP': x[2], 'Destination IP': x[4],
        'Frame Length': str(length), 'Additional Information': packet_dict }
    elif x[2] == 'ARP' or x[2] == 'at' :
        #print(packet.summary())
        data[str(i)] = {'Frame Number': str(i),
        'Protocol': "ARP", 'Source IP': x[5], 'Destination IP': x[7],
        'Frame Length': str(length), 'Additional Information': packet_dict }

    elif 'SNAP' in x:
        try:
            index = x.index('>')
            data[str(i)] = {'Frame Number': str(i),
                        'Protocol': "VRRP", 'Source IP': x[index-1], 'Destination IP': x[index+1],
                        'Frame Length': str(length), 'Additional Information': packet_dict}
        except:
            data[str(i)] = {'Frame Number': str(i),
                            'Protocol': "SNAP", 'Source IP': packet_dict["Ethernet"]["src"],
                            'Destination IP': packet_dict["Ethernet"]["dst"],
                            'Frame Length': str(length), 'Additional Information': packet_dict}

    elif x[5] == '89':
        data[str(i)] = {'Frame Number': str(i),
        'Protocol': "OSPF", 'Source IP': x[2], 'Destination IP': x[4],
        'Frame Length': str(length), 'Additional Information': packet_dict }

    elif x[-1] == 'ICMPv6MLReport2':
        data[str(i)] = {'Frame Number': str(i),
            'Protocol': "ICMPv6MLReport2", 'Source IP': x[2], 'Destination IP': x[4],
            'Frame Length': str(length), 'Additional Information': packet_dict}

    elif x[5] == '2':
        #print(packet.summary())
        data[str(i)] = {'Frame Number': str(i),
        'Protocol': "IGMP", 'Source IP': x[2], 'Destination IP': x[4],
        'Frame Length': str(length), 'Additional Information': packet_dict }

    elif x[2] =='IP' or x[2] =='IPv6':
        data[str(i)] = {'Frame Number': str(i),
                'Protocol': x[4], 'Source IP': x[5], 'Destination IP': x[7],
                'Frame Length': str(length), 'Additional Information': packet_dict}

    elif 'VRRP' in x:
        index = x.index('>')
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': "VRRP", 'Source IP': x[index-1], 'Destination IP': x[index+1],
                        'Frame Length': str(length), 'Additional Information': packet_dict}

    elif x[5] == 'udp':
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': "UDP", 'Source IP': x[2], 'Destination IP': x[4],
                        'Frame Length': str(length), 'Additional Information': packet_dict}

    elif 'IP' in x:
        index = x.index('IP')
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': x[index+2], 'Source IP': x[index +3], 'Destination IP': x[index + 5],
                        'Frame Length': str(length), 'Additional Information': packet_dict}


    elif 'IPv6' in x:
        index = x.index('IPv6')
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': x[index + 2], 'Source IP': x[index + 3], 'Destination IP': x[index + 5],
                        'Frame Length': str(length), 'Additional Information': packet_dict}

    elif x[3] == '(0x8035)' or x[3] == '(MPLS)':

        x[3] = 'RARP' if x[3] == '(0x8035)' else 'MPLS'
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': x[3], 'Source IP': x[0], 'Destination IP': x[2],
                        'Frame Length': str(length), 'Additional Information': packet_dict}

    elif '(0x9000)' in x:
        index = x.index('(0x9000)')
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': 'LOOP', 'Source IP': x[index-3], 'Destination IP': x[index-1],
                        'Frame Length': str(length), 'Additional Information': packet_dict}

    elif 'LLC' in x:
        index = x.index('>')
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': 'LLC', 'Source IP': x[index-1], 'Destination IP': x[index+1],
                        'Frame Length': str(length), 'Additional Information': packet_dict}

    elif 'ARP' in x or 'STP' in x:
        dedo = 'ARP' if ('ARP' in x) else 'STP'
        sip = packet_dict["Ethernet"]
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': dedo, 'Source IP': packet_dict["Ethernet"]["src"], 'Destination IP': packet_dict["Ethernet"]["dst"],
                        'Frame Length': str(length), 'Additional Information': packet_dict}

    elif 'PPP' in x:
        try:
            index = x.index('>')
            data[str(i)] = {'Frame Number': str(i),
                            'Protocol': "PPP", 'Source IP': x[index - 1], 'Destination IP': x[index + 1],
                            'Frame Length': str(length), 'Additional Information': packet_dict}
        except:
            data[str(i)] = {'Frame Number': str(i),
                            'Protocol': dedo, 'Source IP': packet_dict["Ethernet"]["src"],
                            'Destination IP': packet_dict["Ethernet"]["dst"],
                            'Frame Length': str(length), 'Additional Information': packet_dict}

    elif 'Dot1Q' in x:
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': 'Dot1Q', 'Source IP': packet_dict["Ethernet"]["src"], 'Destination IP': packet_dict["Ethernet"]["dst"],
                        'Frame Length': str(length), 'Additional Information': packet_dict}

    elif '>' in x:
        index = x.index('>')
        data[str(i)] = {'Frame Number': str(i),
                        'Protocol': x[index+2], 'Source IP': x[index - 1], 'Destination IP': x[index + 1],
                        'Frame Length': str(length), 'Additional Information': packet_dict}

    elif x[2] == ">":
        data[str(i)] = {'Frame Number': str(i),
        'Protocol': x[7], 'Source IP': x[1], 'Destination IP': x[3],
        'Frame Length': str(length), 'Additional Information': packet_dict }

    elif x[4] == "/" or x[4]=="has":
        try:
            data[str(i)] = {'Frame Number': str(i),
            'Protocol': x[2], 'Source IP': x[5], 'Destination IP': x[7],
            'Frame Length': str(length), 'Additional Information': packet_dict }
        except:
            if x[3] == "(0x9000)":
                x[3] = "Enet config test / 0x9000"
                data[str(i)] = {'Frame Number': str(i),
                'Protocol': x[3], 'Source IP': x[0], 'Destination IP': x[0],
                'Frame Length': str(length), 'Additional Information': packet_dict }

    elif x[4] != "/" or x[4]!="has":
        data[str(i)] = {'Frame Number': str(i),
        'Protocol': x[4], 'Source IP': x[5], 'Destination IP': x[7],
        'Frame Length': str(length), 'Additional Information': packet_dict }

    if 'TCP' in packet_dict.keys():
        try:
            if int(data[str(i)]["Additional Information"]["TCP"]["sport"]) not in list(tcpportlist.keys()):
                tcpport = data[str(i)]["Additional Information"]["TCP"]["sport"]
                tcpportlist[int(tcpport)] = 1
            else:
                tcpportlist[int(tcpport)] = tcpportlist.get(int(tcpport)) + 1
        except :
                pass
    elif 'UDP' in packet_dict.keys():
        try:
            if int(data[str(i)]["Additional Information"]["UDP"]["sport"]) not in list(udpportlist.keys()):
                udpport = data[str(i)]["Additional Information"]["UDP"]["sport"]
                udpportlist[int(udpport)] = 1
            else:
                udpportlist[int(udpport)] = udpportlist.get(int(udpport)) + 1
        except :
                pass

    for proto, port in list(protocol.items()):
        try:
            if 'TCP' in data[str(i)]["Additional Information"].keys():
                if data[str(i)]["Additional Information"]["TCP"]["sport"] in port:
                    data[str(i)]["Protocol"] = proto

            elif 'UDP' in data[str(i)]["Additional Information"].keys():

                if int(data[str(i)]["Additional Information"]["UDP"]["sport"]) in port:

                    data[str(i)]["Protocol"] = proto
        except :
            pass
    #print(list(ip_new.keys()))
    temp = packet.sprintf("%IP.src%,%IP.dst%")
    if temp == "??,??":
        try:
            print(str(data[str(i)]["Additional Information"]["802.3"]["src"])+","+str(data[str(i)]["Additional Information"]["802.3"]["dst"]))
        except:
            print(str(i))
    else:
        #print(IP.src)
        print(temp)
    if (data[str(i)]["Source IP"], data[str(i)]["Destination IP"]) in list(ip_new.keys()):
        ip_new[(data[str(i)]["Source IP"], data[str(i)]["Destination IP"])] = ip_new[(data[str(i)]["Source IP"], data[str(i)]["Destination IP"])] + 1
    else:
        ip_new[(data[str(i)]["Source IP"], data[str(i)]["Destination IP"])] = 1
    
    



with open('data.json', 'w') as f:
    json.dump(data, f,indent=4)

print("/////////// JSON EXPORT DONE ////////////")
#zzz
# PART 3
print("/////////// IDENTIFYING DEVICES USED ////////////")
ports_tcp = [ 10307, 10311, 10364 , 10365, 10407, 10409, 10410, 10412, 10414 , 10415, 10428, 10431, 10432,
            10447, 10449, 10450, 12316, 12645, 12647 , 12648, 13722, 13724,
            13782 , 13783, 38589, 38593, 38600, 38971, 39129, 39278, 4000 ,
            55555, 45678, 1541, 18000, 11001, 5450,  50001,50002,50003,50004,50005,50006,50007, 50008, 50009,50010,50011,50012,50013,50014,50015, 50016, 50018 , 50019,  50025 , 50026, 50027, 50028, 50110 , 50111,
            38000 , 38001, 38011 , 38012, 38014 , 38015, 38200, 38210, 38301, 38400, 38700, 62900, 62911, 62924, 62930, 62938, 62956 , 62957, 62963, 62981 , 62982, 62985, 62992, 63012, 63027 ,63028,63029,63030,63031,63032,63033,63034,
            63035, 63036, 63041, 63075, 63079, 63082, 63088, 63094, 65443, 5052, 5065, 12135,12136, 12137,
            56001, 56002, 56003, 56004, 56005, 56006, 56007, 56008, 56009, 56010, 56011, 56012, 56013, 56014, 56015, 56016, 56017, 56018, 56019, 56020, 56021, 56022, 56023, 56024, 56025, 56026, 56027, 56028, 56029, 56030, 56031, 56032, 56033, 56034, 56035, 56036, 56037, 56038, 56039, 56040,
            56041, 56042, 56043, 56044, 56045, 56046, 56047, 56048, 56049, 56050, 56051, 56052, 56053, 56054, 56055, 56056, 56057, 56058, 56059, 56060, 56061, 56062, 56063, 56064, 56065, 56066, 56067, 56068, 56069, 56070, 56071, 56072, 56073, 56074, 56075, 56076, 56077, 56078, 56079, 56080,
            56081, 56082, 56083, 56084, 56085, 56086, 56087, 56088, 56089, 56090, 56091, 56092, 56093, 56094, 56095, 56096, 56097, 56098, 56099, 9600
            ]
ports_udp = [1541,4000,55555,45678,11001,9600,47808, 5050 , 5051, 50020 ,50021]
ABB = [ 10307, 10311, 10364 , 10365, 10407, 10409, 10410, 10412, 10414 , 10415, 10428, 10431, 10432,
            10447, 10449, 10450, 12316, 12645, 12647 , 12648, 13722, 13724,
            13782 , 13783, 38589, 38593, 38600, 38971, 39129, 39278]
Emerson_Fisher = [4000]
Foxboro_FoxApi = [55555]
Foxboro_AIMAPI = [45678]
Foxboro_Informix = [1541]
Iconics = [18000]
johnson_n1 = [11001]
johnson_bacnet = [47808]
osisoft = [5450]
seimens = [50001,50002,50003,50004,50005,50006,50007, 50008, 50009,50010,50011,50012,50013,50014,50015, 50016, 50018 , 50019, 50020 ,50021, 50025 , 50026, 50027, 50028, 50110 , 50111]
snc = [38000 , 38001, 38011 , 38012, 38014 , 38015, 38200, 38210, 38301, 38400, 38700, 62900, 62911, 62924, 62930, 62938, 62956 , 62957, 62963, 62981 , 62982, 62985, 62992, 63012, 63027 ,63028,63029,63030,63031,63032,63033,63034,63035, 63036, 63041, 63075, 63079, 63082, 63088, 63094, 65443]
telvent = [5050 , 5051, 5052, 5065, 12135,12136, 12137,
            56001, 56002, 56003, 56004, 56005, 56006, 56007, 56008, 56009, 56010, 56011, 56012, 56013, 56014, 56015, 56016, 56017, 56018, 56019, 56020, 56021, 56022, 56023, 56024, 56025, 56026, 56027, 56028, 56029, 56030, 56031, 56032, 56033, 56034, 56035, 56036, 56037, 56038, 56039, 56040,
            56041, 56042, 56043, 56044, 56045, 56046, 56047, 56048, 56049, 56050, 56051, 56052, 56053, 56054, 56055, 56056, 56057, 56058, 56059, 56060, 56061, 56062, 56063, 56064, 56065, 56066, 56067, 56068, 56069, 56070, 56071, 56072, 56073, 56074, 56075, 56076, 56077, 56078, 56079, 56080,
            56081, 56082, 56083, 56084, 56085, 56086, 56087, 56088, 56089, 56090, 56091, 56092, 56093, 56094, 56095, 56096, 56097, 56098, 56099]
omron = [9600]

for port,val in list(tcpportlist.items()):
    if port in ports_tcp:
        if port in ABB:
            del tcpportlist[port]
            final['ABB Ranger 2003'] = val
        elif port in Emerson_Fisher:
            del tcpportlist[port]
            final['Emerson Fisher ROC Plus']  = val
        elif port in Foxboro_FoxApi:
            del tcpportlist[port]
            final['Foxboro/Invensys DCS FoxApi'] = val
        elif port in Foxboro_AIMAPI:
            del tcpportlist[port]
            final['Foxboro/Invensys DCS AIMAPI']  = val
        elif port in Foxboro_Informix:
            del tcpportlist[port]
            final['Foxboro/Invensys DCS Informix'] = val
        elif port in Iconics:
            del tcpportlist[port]
            final['Iconics Genesis32 GenBroker'] = val
        elif port in johnson_n1:
            del tcpportlist[port]
            final['Johnson Controls Metasys N1'] = val
        elif port in johnson_bacnet:
            del tcpportlist[port]
            final['Johnson Controls Metasys BACNet'] = val
        elif port in osisoft:
            del tcpportlist[port]
            final['OSIsoft PI Server'] = val
        elif port in seimens:
            del tcpportlist[port]
            final['Siemens Spectrum Power TG'] = val
        elif port in snc:
            del tcpportlist[port]
            final['SNC GENe']  = val
        elif port in telvent:
            del tcpportlist[port]
            final['Telvent OASyS DNA']  = val
        elif port in omron:
            del tcpportlist[port]
            final['OMRON FINS']  = val

for port, val in list(udpportlist.items()):
    if port in ports_udp:
        if port in ABB:
            del udpportlist[port]
            final['ABB Ranger 2003']  = val
        elif port in Emerson_Fisher:
            del udpportlist[port]
            final['Emerson Fisher ROC Plus'] = val
        elif port in Foxboro_FoxApi:
            del udpportlist[port]
            final['Foxboro/Invensys DCS FoxApi']  = val
        elif port in Foxboro_AIMAPI:
            del udpportlist[port]
            final['Foxboro/Invensys DCS AIMAPI']  = val
        elif port in Foxboro_Informix:
            del udpportlist[port]
            final['Foxboro/Invensys DCS Informix']  = val
        elif port in Iconics:
            del udpportlist[port]
            final['Iconics Genesis32 GenBroker']  = val
        elif port in johnson_n1:
            del udpportlist[port]
            final['Johnson Controls Metasys N1'] = val
        elif port in johnson_bacnet:
            del udpportlist[port]
            final['Johnson Controls Metasys BACNet']  = val
        elif port in osisoft:
            del udpportlist[port]
            final['OSIsoft PI Server'] = val
        elif port in seimens:
            del udpportlist[port]
            final['Siemens Spectrum Power TG'] = val
        elif port in snc:
            del udpportlist[port]
            final['SNC GENe']  = val
        elif port in telvent:
            del udpportlist[port]
            final['Telvent OASyS DNA'] = val
        elif port in omron:
            del udpportlist[port]
            final['OMRON FINS'] = val


with open('device.json', 'w') as f:
    json.dump(final, f,indent=4)
print("/////////// IDENTIFYING DEVICES DONE ////////////")
print("/////////// PAYLOAD CHECK ////////////")

j = i
i = 1

transfer = []
transfer2 = []
for packet in packets:

    mac = getmacbyip()

    
    mac = OuiLookup().query(str(data[str(i)]["Additional Information"]["Ethernet"]["src"]))
    #print(str(data[str(i)]["Additional Information"]["Ethernet"]["dst"]))
    mac2 = OuiLookup().query(str(data[str(i)]["Additional Information"]["Ethernet"]["dst"]))
    #print(list(mac2[0].items())[0][1])

    
    #print(list(mac[0].items())[0][1])
    temp = []
    temp.append(data[str(i)]['Source IP'])
    temp.append(data[str(i)]['Destination IP'])
    temp.append(list(mac[0].items())[0][1])
    temp.append(list(mac2[0].items())[0][1])
    #print(temp)
    i = i + 1
    transfer.append(temp)

ip_new = dict(sorted(ip_new.items(),key=lambda item: item[1], reverse=True))
i=int(0)
for key in ip_new.keys():
    if i<10:
        #print(key)
        newance = []
        newance.append(key[0])
        newance.append(key[1])
        newance.append(ip_new[key])
        #print(newance)
        transfer2.append(newance)
    i = i+1
#print(transfer2)
    

#print(transfer2)
#print(transfer)
tabling = tabulate(transfer, headers=["Src IP Address", "Dst IP Address", "Vendor Device Src", "Vendor Device Dst"])
#print(transfer2)
tabling2 = tabulate(transfer2, headers=["Src IP Address", "Dst IP Address", "Number of Packets Shared"])


print("/////////// PAYLOAD CHECK DONE ////////////")
print("/////////// COMPILING REPORT ////////////")
#print(ip_new)
#print(tabling2)
#print(tabling)
with open('report.txt', 'w') as f:
    f.write("Top 10 IP Addresses which exchange packets : \n\n")
    f.write(tabling2)
with open('report.txt', 'a') as f:
    f.write("\n\n\nVendor Name Derived from Payload : \n\n")
    f.write(tabling)