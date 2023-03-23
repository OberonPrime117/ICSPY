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
'''
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
    ranking("protocol",proto_val,es)
    ranking("srcdst",sip,es,dip)
    ranking("srcip",sip,es)
    ranking("dstip",dip,es)

    if svendor == None:
        pass
    else:
        ranking("vendors",svendor,es)
    
    if dvendor == None:
        pass
    else:
        ranking("vendors",dvendor,es)
    
    ranking("srcport",sport,es)
    ranking("dstport",dport,es)
'''