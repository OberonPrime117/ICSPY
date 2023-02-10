from datetime import datetime
from elasticsearch import Elasticsearch
import requests
ELASTIC_PASSWORD = "-jnEVq4pt66m9GDJpxQy"
payload = open("/home/aditya/Documents/GitHub/python-pcap-parser/mac-vendors.json",'r').read()
response=requests.put("http://localhost:9200/elastic2/external/1?pretty",auth=("elastic", ELASTIC_PASSWORD),data=payload)
print(response.text)