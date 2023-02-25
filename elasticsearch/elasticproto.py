from datetime import datetime
from elasticsearch import Elasticsearch
import json
import requests

def index_doc(es):
  i = 0
  for b in dicta:
    i = i+1
    resp = es.index(index="vendor-name",id=i,document=b)
    print(resp)
  return i

def search():
  ELASTIC_PASSWORD = "1Q_OlVC5SGUTpoY-kD=O"
  es = Elasticsearch("https://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD),verify_certs=False)
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
  resp = es.search(index="vendor-name", body=searchp)
  print(resp["hits"]["hits"][0]["_source"]["Vendor Name"])



def refresh_index(es):
  es.indices.refresh(index="vendor-name")

def get_doc(es,i = 81291):
  while i>0:
    resp = es.get(index="vendor-name")
    print(resp['_source'])
    i = i-1

# IF INDEX DOES NOT EXIST
# es.indices.create(index="indexname")

# GET ALL INDICES
# print(es.indices.get_alias())

# DELETE ALL INDICES
# es.indices.delete(index='macvendors')
ELASTIC_PASSWORD = "1Q_OlVC5SGUTpoY-kD=O"
es = Elasticsearch("https://localhost:9200",http_auth=("elastic", ELASTIC_PASSWORD),verify_certs=False)
i = index_doc(es)
refresh_index(es)
#search()
get_doc(es,i)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
# print(i)