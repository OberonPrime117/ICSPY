import json
from tkinter import filedialog as fd
from scapy.all import *
from scapy.all import Ether
from tkinter.messagebox import showinfo
from scapy.all import Ether, IP
import os
from scapy.all import * 
import pandas as pd 
import numpy as np 
from sys import exit
import binascii 
import matplotlib.pyplot as plt
from tkinter import filedialog as fd
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
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
tcpportlist = {}
udpportlist = {}
packet_dict = {}
protocol = {"BACnet":[47808], "DNP3": [20000,20000], "EtherCAT": [34980], "Ethernet/IP" : [44818,2222,44818],
            "FL-net" : [55000 , 55001 ,55002 ,55003 ] , "Foundation Fieldbus HSE": [1089 ,1090 ,1091, 1089  ], "ICCP":[102], "Modbus TCP":[502],
            "OPC UA Discovery Server" : [4840], "OPC UA XML": [80,443], "PROFINET": [34962 ,34963 ,34964],"ROC Plus" : [4000]}

keys_to_remove = {"802.3","Ethernet"}

for packet in packets:
    length = len(packet)
    i += 1
    x = str(packet.summary()).split(" ")
    y = str(packet.show())
    for line in packet.show2(dump=True).split('\n'):
        if '###' in line:
            layer = line.strip('#[] ')
            packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            packet_dict[layer][key.strip()] = val.strip()
    
    #e = frame[Ether]
    #print(e.src,e.dst)

    if x[2] == ">":
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
    
    for key in keys_to_remove:
        try:
            del data[str(i)]["Additional Information"]["802.3"]
            del data[str(i)]["Additional Information"]["Ethernet"]
        except KeyError:
            pass
    
    if "TCP" in packet_dict.keys(): 
        if data[str(i)]["Additional Information"]["TCP"]["sport"] not in tcpportlist:
            tcpport = data[str(i)]["Additional Information"]["TCP"]["sport"]
            tcpportlist[int(tcpport)] = 1
        else:
            tcpportlist[int(tcpport)] += 1
    elif "UDP" in packet_dict.keys():
        if data[str(i)]["Additional Information"]["UDP"]["sport"] not in udpportlist:
            udpport = data[str(i)]["Additional Information"]["UDP"]["sport"]
            udpportlist[int(udpport)] = 1
        else:
            udpportlist[int(udpport)] += 1
    
    
    for proto, port in list(protocol.items()):
        if 'TCP' in data[str(i)]["Additional Information"].keys(): 
            if data[str(i)]["Additional Information"]["TCP"]["sport"] in port:
                data[str(i)]["Protocol"] = proto
        elif 'UDP' in data[str(i)]["Additional Information"].keys():
            if int(data[str(i)]["Additional Information"]["UDP"]["sport"]) in port:
                print("DUCK")
                data[str(i)]["Protocol"] = proto
    
    


with open('data.json', 'w') as f:
    json.dump(data, f,indent=4)


#zzz

num_of_packets_to_sniff = 100
pcap = sniff(count=num_of_packets_to_sniff)


pcap = pcap + rdpcap(filep)


ethernet_frame = pcap[101]
ip_packet = ethernet_frame.payload
segment = ip_packet.payload
data = segment.payload 

ethernet_frame.show()

ethernet_type = type(ethernet_frame)
ip_type = type(ip_packet)
tcp_type = type(segment)

ip_fields = [field.name for field in IP().fields_desc]
tcp_fields = [field.name for field in TCP().fields_desc]
udp_fields = [field.name for field in UDP().fields_desc]

dataframe_fields = ip_fields + ['time'] + tcp_fields + ['payload','payload_raw','payload_hex']


df = pd.DataFrame(columns=dataframe_fields)
for packet in pcap[IP]:

    field_values = []

    for field in ip_fields:
        if field == 'options':

            field_values.append(len(packet[IP].fields[field]))
        else:
            field_values.append(packet[IP].fields[field])
    
    field_values.append(packet.time)
    
    layer_type = type(packet[IP].payload)
    for field in tcp_fields:
        try:
            if field == 'options':
                field_values.append(len(packet[layer_type].fields[field]))
            else:
                field_values.append(packet[layer_type].fields[field])
        except:
            field_values.append(None)
    

    field_values.append(len(packet[layer_type].payload))
    field_values.append(packet[layer_type].payload.original)
    field_values.append(binascii.hexlify(packet[layer_type].payload.original))

    df_append = pd.DataFrame([field_values], columns=dataframe_fields)
    df = pd.concat([df, df_append], axis=0)

df = df.reset_index()
df = df.drop(columns="index")
print("////////////////")
print(df['sport'])
print(df['dport'])
frequent_address = df['src'].describe()['top']

source_addresses = df.groupby("src")['payload'].sum()
source_addresses.plot(kind='bar',title="Addresses Sending Payloads",figsize=(18,14))
#plt.show()
plt.savefig('address_sending_payload.jpg')

destination_addresses = df.groupby("dst")['payload'].sum()
destination_addresses.plot(kind='bar', title="Destination Addresses (Bytes Received)",figsize=(18,14))
#plt.show()
plt.savefig('address_receiving_payload.jpg')

source_payloads = df.groupby("sport")['payload'].sum()
source_payloads.plot(kind='bar',title="Source Ports (Bytes Sent)",figsize=(18,14))
#plt.show()
plt.savefig('source_ports.jpg')

destination_payloads = df.groupby("dport")['payload'].sum()
destination_payloads.plot(kind='bar',title="Destination Ports (Bytes Received)",figsize=(18,14))
#plt.show()
plt.savefig('destination_ports.jpg')

frequent_address_df = df[df['src']==frequent_address]
frequent_address_groupby = frequent_address_df[['src','dst','payload']].groupby("dst")['payload'].sum()
print(frequent_address_df[['src','dst','payload']])

frequent_address_groupby.plot(kind='bar',title="Most Frequent Address is Speaking To (Bytes)",figsize=(18,14))
#plt.show()
plt.savefig('frequent_address.jpg')
print(tcpportlist)
print(udpportlist)

#IDENTIFYING DEVICES FOR PORTS 
# PART 3

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
            del udpportlist[port]
            final['ABB Ranger 2003'] = val
        elif port in Emerson_Fisher:
            del udpportlist[port]
            final['Emerson Fisher ROC Plus']  = val
        elif port in Foxboro_FoxApi:
            del udpportlist[port]
            final['Foxboro/Invensys DCS FoxApi'] = val
        elif port in Foxboro_AIMAPI:
            del udpportlist[port]
            final['Foxboro/Invensys DCS AIMAPI']  = val
        elif port in Foxboro_Informix:
            del udpportlist[port]
            final['Foxboro/Invensys DCS Informix'] = val
        elif port in Iconics:
            del udpportlist[port]
            final['Iconics Genesis32 GenBroker'] = val
        elif port in johnson_n1:
            del udpportlist[port]
            final['Johnson Controls Metasys N1'] = val
        elif port in johnson_bacnet:
            del udpportlist[port]
            final['Johnson Controls Metasys BACNet'] = val
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
            final['Telvent OASyS DNA']  = val
        elif port in omron:
            del udpportlist[port]
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
            

print(final)

with open('device.json', 'w') as f:
    json.dump(final, f,indent=4)