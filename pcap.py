# ////////////////// ALL IMPORTS ////////////////////////

from elasticsearch import Elasticsearch # SEARCHING
from dotenv import dotenv_values
from work import work
from functions.delete import delete
import multiprocessing
import argparse
from scapy.all import PcapReader
import socket
import sys
import threading

def animatepi(i):
    new_sizes = []
    new_sizes = random.sample(sizes, len(sizes))
    print(new_sizes)
    ax.clear()
    ax.axis('equal')
    ax.pie(new_sizes, labels=labels, autopct='%1.1f%%', shadow=True, startangle=140) 

if __name__ == "__main__":
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--pcap", help = "Enter your pcap file")
    args = parser.parse_args()

    if args.pcap:
        packets = PcapReader(args.pcap)
        print(packets)
    else:
        sys.exit()
    
    data = {}

    p1 = threading.Thread(target=delete,args=(es,))
    p2 = threading.Thread(target=work,args=(es,packets))
    
    p1.start()
    p1.join()
    p2.start()
    
    p2.join()
    print("Done!")
