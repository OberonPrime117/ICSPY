from dotenv import dotenv_values
from elasticsearch import Elasticsearch
import time 
import multiprocessing

def ranking(esindex,esid,es,secondid=None):
    try:
        resp = es.get(index=esindex,id=esid)
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        resp = es.index(index=esindex, id=esid, document=a)

    except:
        if secondid == None:
            dbody = {"Number of Packets" : 1}
        else:
            dbody = {"Number of Packets" : 1, "Destination IP": secondid}
        resp = es.index(index=esindex, id=esid, document=dbody)
    
def rankme(es,data):
    dmac = data["Destination MAC"]
    smac = data["Source MAC"]
    dip = data["Destination IP"]
    sip = data["Source IP"]
    dport = data["Destination Port"]
    sport = data["Source Port"]
    proto_val = data["Protocol"]
    dvendor = data["Destination Vendor"]
    svendor = data["Source Vendor"]
    start = time.process_time()
    r1 = multiprocessing.Process(target=ranking , args=("protocol",proto_val,es))
    r1.start()
    r2 = multiprocessing.Process(target=ranking , args=("srcdst",sip,es,dip))
    r2.start()
    r3 = multiprocessing.Process(target=ranking , args=("srcip",sip,es))
    r3.start()
    r4 = multiprocessing.Process(target=ranking , args=("dstip",dip,es))
    r4.start()
    if svendor == None:
        pass
    else:
        r5 = multiprocessing.Process(target=ranking , args=("vendors",svendor,es))
        r5.start()
    if dvendor == None:
        pass
    else:
        r6 = multiprocessing.Process(target=ranking , args=("vendors",dvendor,es))
        r6.start()
    r7 = multiprocessing.Process(target=ranking , args=("srcport",sport,es))
    r7.start()
    r8 = multiprocessing.Process(target=ranking , args=("dstport",dport,es))
    r8.start()

    r1.join()
    r2.join()
    r3.join()
    r4.join()
    if svendor == None:
        pass
    else:
        r5.join()
    if dvendor == None:
        pass
    else:
        r6.join()
    r7.join()
    r8.join()