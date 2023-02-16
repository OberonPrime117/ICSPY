from datetime import datetime
from elasticsearch import Elasticsearch
import json
import requests

def index_doc():
  payload = open("mac-vendors.json")
  with open("mac-vendors.json", encoding='utf-8-sig') as f:
    read = f.read()
    dicta = json.loads(read)
  i = 0
  for b in dicta:
    i = i+1
    b = { "word" : b}
    print(b)
    resp = es.index(index="test",id=i,document=b)
    print(resp['result'])
  return i

def search():
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
  print(resp)


def refresh_index():
  es.indices.refresh(index="test")

def get_doc(i = 81291):
  while i>0:
    resp = es.get(index="test",id=i)
    print(resp['_source'])
    i = i-1

ELASTIC_PASSWORD = "jUjRG50hi-co+9_c=bE9"
es = Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

# IF INDEX DOES NOT EXIST
# es.indices.create(index="indexname")

# GET ALL INDICES
# print(es.indices.get_alias())

# DELETE ALL INDICES
# es.indices.delete(index='macvendors')

i = index_doc()
refresh_index()
#search()
get_doc(i)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
