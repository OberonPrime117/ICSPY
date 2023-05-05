from datetime import datetime
from elasticsearch import Elasticsearch
import json
import requests
import os
from dotenv import dotenv_values
import time

def index_doc(es):
  headers = {'Content-Type': 'application/json','Accept': 'application/json'}
  with open("protocol.json", encoding='utf-8-sig') as f:
    read = f.read()
    dicta = json.loads(read)
  i = 0
  for b in dicta:
    a = list(b.keys())

    h=a[0]
    g={ "Protocol Name": b[h] }
    print(g)

    resp = es.index(index="elasticproto",id=h,body=g)
    #time.sleep(1)
    
    print(resp)
  return i

def search():
  headers = {'Content-Type': 'application/json','Accept': 'application/json'}
  es = Elasticsearch("http://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD))
  searchp = {
  "query": {
    "match": {
      "Mac Prefix":{
        "query": "00-D0-EF"
      }
    }
  }
}
  resp = es.search(index="mac-vendors", body=searchp)
  print(resp["hits"]["hits"][0]["_source"]["Vendor Name"])



def refresh_index(es):
  es.indices.refresh(index="elasticproto")

def get_doc(es):
  resp = es.get(index="mac-vendors", id="D8:97:90")
  print(resp['_source'])


# IF INDEX DOES NOT EXIST
# es.indices.create(index="indexname")

# GET ALL INDICES
# print(es.indices.get_alias())

# DELETE ALL INDICES
# es.indices.delete(index='macvendors')
config = dotenv_values("../.env")
ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
headers = {'Content-Type': 'application/json','Accept': 'application/json'}

ELASTIC_PASSWORD = "=32pcSO6OOtiGBcjKs19"
es =  Elasticsearch("https://localhost:9200", http_auth=("elastic", ELASTIC_PASSWORD),verify_certs=False)

#es.indices.delete(index='elasticproto')
i = index_doc(es)
refresh_index(es)
#search()
#get_doc(es)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
# print(i)