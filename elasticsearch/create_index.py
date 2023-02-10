from datetime import datetime
from elasticsearch import Elasticsearch
import requests
ELASTIC_PASSWORD = "-jnEVq4pt66m9GDJpxQy"
response=requests.put("http://localhost:9200/elastic2",auth=("elastic", ELASTIC_PASSWORD))
print(response.text)
#es = Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))
#print(es.info().body)
#MyFile= open("/home/aditya/Documents/GitHub/python-pcap-parser/mac-vendors.json",'r').read()
#print(MyFile)
#es.create(index='macvendors',id=1, document=MyFile)
#es.indices.delete(index='macvendors')