from datetime import datetime
from elasticsearch import Elasticsearch
import json
import requests
import os
import time

def index_doc(es):
  headers = {'Content-Type': 'application/json','Accept': 'application/json'}
  with open("vendor.json", encoding='utf-8-sig') as f:
    read = f.read()
    dicta = json.loads(read)
  i = 0
  for b in dicta:
    h=str(b["Mac Prefix"])
    g={ "Vendor Name": b["Vendor Name"] }

    resp = es.index(index="mac-vendors",id=h,body=g)
    #time.sleep(1)
    
    print(resp)
  return i

def search():
  # config = dotenv_values(".env")
  # ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
  headers = {'Content-Type': 'application/json','Accept': 'application/json'}
  es = Elasticsearch("http://localhost:9200",http_auth=("elastic", AWS_ELASTIC_PASSWORD))
  #value = str(input("Enter mac address to search : "))
  #searchtime = value
  #searchp = {"Mac Prefix" : ""}
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
  es.indices.refresh(index="mac-vendors")

def get_doc(es):
  resp = es.get(index="mac-vendors", id="D8:97:90")
  print(resp['_source'])


# IF INDEX DOES NOT EXIST
# es.indices.create(index="indexname")

# GET ALL INDICES
# print(es.indices.get_alias())

# DELETE ALL INDICES
# es.indices.delete(index='macvendors')
#config = dotenv_values("../.env")
#ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
#headers = {'Content-Type': 'application/json','Accept': 'application/json'}
AWS_ELASTIC_PASSWORD = "Lc6Hb=asU1TOhDHgPS5M"
ELASTIC_PASSWORD = "z=f1p=Xrl2NkwM6fpoXr"
es =  Elasticsearch("https://ec2-3-110-28-38.ap-south-1.compute.amazonaws.com:9200", http_auth=("elastic", AWS_ELASTIC_PASSWORD), verify_certs=False)
#es.indices.delete(index='mac-vendors')
i = index_doc(es)
refresh_index(es)
#search()
#get_doc(es)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
# print(i)