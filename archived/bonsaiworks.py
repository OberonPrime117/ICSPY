from elasticsearch import Elasticsearch
import json

def index_doc(es):
    with open("vendor.json", encoding='utf-8-sig') as f:
        read = f.read()
        dicta = json.loads(read)
    i = 0
    for b in dicta:
        h = str(b["Mac Prefix"])
        g = {"Vendor Name": b["Vendor Name"]}

        resp = es.index(index="mac-vendors", doc_type="_doc", id=h, body=g)
        # time.sleep(1)

        print(resp)
    return i


def search(es):

    searchp = {
        "query": {
            "match": {
                "Mac Prefix": {
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


AWS_EC2 = "https://saflu608fd:hn4wq7ssu4@testing-6258629515.us-east-1.bonsaisearch.net:443"
es = Elasticsearch(AWS_EC2, verify_certs=False)
# es.indices.create(index="mac-vendors")
# i = index_doc(es)
# refresh_index(es)

# DELETE INDICE FOR CLEAN REDO OF DATA POPULATION
# es.indices.delete(index='mac-vendors')

# SEARCH A DATA POINT OVER ELASTICSEARCH
# search(es)

# EXTRACT DATA FROM INDEX
# get_doc(es)

# DELETE ALL INDICES
es.indices.delete(index='mac-vendors')
