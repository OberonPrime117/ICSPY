from datetime import datetime
from elasticsearch import Elasticsearch
import json
import requests
ELASTIC_PASSWORD = "jUjRG50hi-co+9_c=bE9"
es = Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

# IF INDEX DOES NOT EXIST
# es.indices.create(index="indexname")

# GET ALL INDICES
# print(es.indices.get_alias())

# DELETE ALL INDICES
# es.indices.delete(index='macvendors')

payload = open("mac-vendors.json")
with open("mac-vendors.json", encoding='utf-8-sig') as f:
  read = f.read()
  dicta = json.loads(read)

i = 0
for b in dicta:
  #b = {i:b}
  i = i +1

  #print(b)
  #print(type(b))
  resp = es.index(index="elastic3",id=i,document=b)
  print(resp['result'])
  #resp = es.index(index="elastic3",id=i)
  #a = "http://localhost:9200/elastic2/_doc/"+str(i)
  #r = requests.put(a, data=a, headers={"Content-Type":"application/json"})

es.indices.refresh(index="elastic3")

while i>0:
  resp = es.get(index="elastic3",id=i)
  print(resp['_source'])
  i = i -1 
#res = es.index(index='elastic2', id=i, body=dicta)
#rel = scan(client=es,query=query,scroll='1m',index='elastic2',raise_on_error=True, preserve_order=False,clear_scroll=True)
#print(rel)
