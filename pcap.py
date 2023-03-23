# ////////////////// ALL IMPORTS ////////////////////////

from elasticsearch import Elasticsearch # SEARCHING
from dotenv import dotenv_values
from work import work
from functions.delete import delete
import multiprocessing
import os
import socket
import sys
import threading

def server():
    os.system("python app.py")

def pcap(filename):

    p3 = multiprocessing.Process(target=server)
    p3.start()

    p1 = multiprocessing.Process(target=delete())
    p1.start()

    p2 = multiprocessing.Process(target=work(filename))
    p2.start()
    p1.join()
    p2.join()
    p3.join()
    print("Done!")
