import os
from elasticsearch import Elasticsearch 
import csv
from functions.visualise import visualise
from dotenv import dotenv_values
import time
import multiprocessing
import threading 

def search(csvfile,test,es):

    searchp = { 
        "match_all" : {}
    }
    #print(test)
    
    resp = es.search(index=test, query=searchp)
    #print(resp)
    #print(resp)
    
    #start = time.process_time()

    for j in resp["hits"]["hits"]:
        #print(j)
        impact = es.get(index=test,id=j["_id"])

        if test == "srcdst":
            with open(csvfile, mode='w', newline='') as f:
                b = ['Source','Destination','Number of Packets']
                writer = csv.writer(f)
                writer.writerow(b)
        b = []
        #print(impact["_id"])
        #print(csvfile)
        b.append(impact["_id"])
        if test == "srcdst":
            b.append(impact["_source"]["Destination IP"])
        b.append(impact["_source"]["Number of Packets"])

        if os.path.isfile(csvfile):
            with open(csvfile, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(b)
        else:
            with open(csvfile, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(b)

def export_data(img_static,csvfile,test,es):
    search(csvfile,test,es)
    visualise(img_static,csvfile)
    '''
    p1 = multiprocessing.Process(target=search , args=(csvfile,test,es))
    p1.start()
    p5 = multiprocessing.Process(target=visualise , args=(img_static,csvfile))
    p5.start()
    
    p1.join()
    p5.join()
    #print(time.process_time() - start)'''

def export(es):
    export_data("static/src-ip.png","results/src-ip.csv","srcip",es)
    export_data("static/dst-ip.png","results/dst-ip.csv","dstip",es)
    export_data("static/vendor.png","results/vendor.csv","vendors",es)
    export_data("static/protocol.png","results/protocol.csv","protocol",es)
    export_data("static/src-port.png","results/src-port.csv","srcport",es)
    export_data("static/dst-port.png","results/dst-port.csv","dstport",es)
    export_data("static/dst-mac.png","results/dst-mac.csv","dstmac",es)
    export_data("static/src-mac.png","results/src-mac.csv","srcmac",es)
    search("results/src-dst.csv","srcdst",es)
    '''
    p1 = multiprocessing.Process(target=export_data , args=("static/src-ip.png","results/src-ip.csv","srcip",es))
    p1.start()
    p2 = multiprocessing.Process(target=export_data , args=("static/dst-ip.png","results/dst-ip.csv","dstip",es))
    p2.start()
    p3 = multiprocessing.Process(target=export_data , args=("static/vendor.png","results/vendor.csv","vendors",es))
    p3.start()
    p4 = multiprocessing.Process(target=export_data , args=("static/protocol.png","results/protocol.csv","protocol",es))
    p4.start()
    p5 = multiprocessing.Process(target=export_data , args=("static/src-port.png","results/src-port.csv","srcport",es))
    p5.start()
    p6 = multiprocessing.Process(target=export_data , args=("static/dst-port.png","results/dst-port.csv","dstport",es))
    p6.start()
    p7 = multiprocessing.Process(target=export_data , args=("static/dst-mac.png","results/dst-mac.csv","dstmac",es))
    p7.start()
    p8 = multiprocessing.Process(target=export_data , args=("static/src-mac.png","results/src-mac.csv","srcmac",es))
    p8.start()

    p1.join()
    p2.join()
    p3.join()
    p4.join()
    p5.join()
    p6.join()
    p7.join()
    p8.join()'''