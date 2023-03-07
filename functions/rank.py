from dotenv import dotenv_values
from elasticsearch import Elasticsearch
import time 
def ranking(esindex,esid,secondid=None):
    
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    try:
        start = time.process_time()
        resp = es.get(index=esindex,id=esid)
        #print(time.process_time() - start)
        a = resp["_source"]
        a["Number of Packets"] = int(a["Number of Packets"]) + 1
        #start = time.process_time()
        resp = es.index(index=esindex, id=esid, document=a)
        #print(time.process_time() - start)

    except:
        if secondid == None:
            dbody = {"Number of Packets" : 1}
        else:
            dbody = {"Number of Packets" : 1, "Destination IP": secondid}
        resp = es.index(index=esindex, id=esid, document=dbody)
    
    