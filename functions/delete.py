import os
from elasticsearch import Elasticsearch
from dotenv import dotenv_values
import csv
import plotly.graph_objects as go
import time
import multiprocessing

def iterate_deletecsv(filename):
    try:
        os.remove(filename)
    except:
        pass

def delete(es):
    es.options(ignore_status=[400,404]).indices.delete(index='srcdst')
    es.options(ignore_status=[400,404]).indices.delete(index='srcip')
    es.options(ignore_status=[400,404]).indices.delete(index='dstip')
    es.options(ignore_status=[400,404]).indices.delete(index='vendors')
    es.options(ignore_status=[400,404]).indices.delete(index='protocol')
    es.options(ignore_status=[400,404]).indices.delete(index='srcport')
    es.options(ignore_status=[400,404]).indices.delete(index='dstport')
    p1 = multiprocessing.Process(target=delete,args=("static/dst-ip.png",))
    p1.start()
    p2 = multiprocessing.Process(target=delete,args=("static/dst-port.png",))
    p2.start()
    p3 = multiprocessing.Process(target=delete,args=("static/protocol.png",))
    p3.start()
    p4 = multiprocessing.Process(target=delete,args=("static/src-ip.png",))
    p4.start()
    p5 = multiprocessing.Process(target=delete,args=("static/src-port.png",))
    p5.start()
    p6 = multiprocessing.Process(target=delete,args=("static/vendor.png",))
    p6.start()
    p7 = multiprocessing.Process(target=delete,args=("static/pair-of-ip.png",))
    p7.start()

    c1 = multiprocessing.Process(target=delete,args=("results/dst-ip.csv",))
    c1.start()
    c2 = multiprocessing.Process(target=delete,args=("results/dst-port.csv",))
    c2.start()
    c3 = multiprocessing.Process(target=delete,args=("results/protocol.csv",))
    c3.start()
    c4 = multiprocessing.Process(target=delete,args=("results/src-ip.csv",))
    c4.start()
    c5 = multiprocessing.Process(target=delete,args=("results/src-port.csv",))
    c5.start()
    c6 = multiprocessing.Process(target=delete,args=("results/vendor.csv",))
    c6.start()
    c7 = multiprocessing.Process(target=delete,args=("results/pair-of-ip.csv",))
    c7.start()

    p1.join()
    p2.join()
    p3.join()
    p4.join()
    p5.join()
    p6.join()
    p7.join()
    c1.join()
    c2.join()
    c3.join()
    c4.join()
    c5.join()
    c6.join()
    c7.join()



