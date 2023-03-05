from datetime import datetime
from elasticsearch import Elasticsearch
import json
import requests


def index_doc(es):
  with open("mac-vendors2.json", encoding='utf-8-sig') as f:
    read = f.read()
    dicta = json.loads(read)
  i = 0
  for b in dicta:
    i = i+1
    h=str(b["Mac Prefix"][0:8]).upper()
    g={ "Vendor Name": b["Vendor Name"] }
    try:
      hello = es.get(index="mac-vendors", id=h)
      print(resp['_source'])
    except:
      resp = es.index(index="mac-vendors",id=h,document=g)
      print(resp)
  return i

def search():
  ELASTIC_PASSWORD = "M_R*tu-=C_98N2GZDoT_"
  es = Elasticsearch("https://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD),verify_certs=True ,ca_certs="../http_ca.crt")
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
ELASTIC_PASSWORD = "M_R*tu-=C_98N2GZDoT_"
es =  Elasticsearch(["https://localhost:9200"],basic_auth=("elastic", ELASTIC_PASSWORD),verify_certs=True ,ca_certs="../http_ca.crt")
es.options(ignore_status=[400,404]).indices.delete(index='mac-vendors')
i = index_doc(es)
refresh_index(es)
#search()
#get_doc(es)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
# print(i)