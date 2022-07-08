import json
from scapy.all import *
import pandas as pd
import binascii
import matplotlib.pyplot as plt
from tkinter import filedialog as fd
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

keys_to_remove = {"802.3"}



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

    #e = frame[Ether]
    #print(e.src,e.dst)

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
        print(packet.summary())
        print(str(i))
        data[str(i)] = {'Frame Number': str(i),
        'Protocol': x[7], 'Source IP': x[1], 'Destination IP': x[3],
        'Frame Length': str(length), 'Additional Information': packet_dict }

    elif x[4] == "/" or x[4]=="has":
        print(packet.summary())
        print(str(i))
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
        print(packet.summary())
        print(str(i))
        data[str(i)] = {'Frame Number': str(i),
        'Protocol': x[4], 'Source IP': x[5], 'Destination IP': x[7],
        'Frame Length': str(length), 'Additional Information': packet_dict }


    for key in keys_to_remove:
        try:
            del data[str(i)]["Additional Information"]["802.3"]
        except KeyError:
            pass

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


with open('data.json', 'w') as f:
    json.dump(data, f,indent=4)

print("/////////// JSON EXPORT DONE ////////////")
#zzz
print("/////////// DATA VISUALIZATION ////////////")
num_of_packets_to_sniff = 100
pcap = sniff(count=num_of_packets_to_sniff)


pcap = pcap + rdpcap(filep)


ethernet_frame = pcap[101]
ip_packet = ethernet_frame.payload
segment = ip_packet.payload
data = segment.payload

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

source_addresses = df.groupby("src")['payload'].sum()
jsona = df.groupby("src")['payload'].sum().to_json('address_sending_payload.json',indent=4)
#with open('address_sending_payload.json', 'w') as f:
#    json.dump(jsona, f,indent=4)
#source_addresses.plot(kind='barh',title="Addresses Sending Payloads",figsize=(11,8))
#plt.show()
#plt.savefig('address_sending_payload.jpg',bbox_inches='tight',dpi=100)

destination_addresses = df.groupby("dst")['payload'].sum()
jsona = df.groupby("dst")['payload'].sum().to_json('address_receiving_payload.json',indent=4)
#with open('address_receiving_payload.json', 'w') as f:
#    json.dump(jsona, f,indent=4)
#destination_addresses.plot(kind='barh', title="Destination Addresses (Bytes Received)",figsize=(11,8))
#plt.show()
#plt.savefig('address_receiving_payload.jpg',bbox_inches='tight',dpi=100)

source_payloads = df.groupby("sport")['payload'].sum()
jsona = df.groupby("sport")['payload'].sum().to_json('source_ports.json',indent=4)
#with open('source_ports.json', 'w') as f:
#    json.dump(jsona, f,indent=4)
#source_payloads.plot(kind='barh',title="Source Ports (Bytes Sent)",figsize=(11,8))
#plt.show()
#plt.savefig('source_ports.jpg',bbox_inches='tight',dpi=100)

destination_payloads = df.groupby("dport")['payload'].sum()
jsona = destination_payloads.to_json('destination_ports.json',indent=4)
#with open('destination_ports.json', 'w') as f:
 #   json.dump(jsona, f,indent=4)
#destination_payloads.plot(kind='barh',title="Destination Ports (Bytes Received)",figsize=(11,8))
#plt.show()
#plt.savefig('destination_ports.jpg',bbox_inches='tight',dpi=100)


# FREQUENT SOURCE ADDRESSES
frequent_address = df['src'].describe()['top']
frequent_address_df = df[df['src']==frequent_address]
frequent_address_groupby = frequent_address_df[['src','dst','payload']].groupby("dst")['payload'].sum()
jsona = frequent_address_groupby.to_json('frequent_address.json',indent=4)
#with open('frequent_src_address.json', 'w') as f:
#    json.dump(jsona, f,indent=4)
#frequent_address_groupby.plot(kind='barh',title="Most Frequent Address is Speaking To (Bytes)",figsize=(11,8))
#plt.show()
#plt.savefig('frequent_src_address.jpg',bbox_inches='tight',dpi=100)

print("/////////// DATA VISUALIZATION DONE ////////////")
#IDENTIFYING DEVICES FOR PORTS
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