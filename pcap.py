# ////////////////// ALL IMPORTS ////////////////////////

import argparse
from elasticsearch import Elasticsearch # SEARCHING
from dotenv import dotenv_values
from work import work
from functions.delete import delete
import multiprocessing
import os
import socket
import sys
import threading
from scapy.all import PcapReader


def pcap(filename):
    #parser = argparse.ArgumentParser()
    #parser.add_argument("-p", "--pcap", help = "Enter your pcap file")
    #args = parser.parse_args()
    #if args.pcap:
    packets = PcapReader(filename)
    #else:
    #    sys.exit()

    p1 = multiprocessing.Process(target=delete())
    p1.start()
    

    p2 = multiprocessing.Process(target=work(packets))
    p2.start()
    p1.join()
    p2.join()
    print("Done!")
