from elasticsearch import Elasticsearch
import json
import threading
from concurrent.futures import ThreadPoolExecutor

def index_doc(es, data, batch_size=50):
    def index_batch(batch):
        for b in batch:
            h = str(b["Mac Prefix"])
            g = {"Vendor Name": b["Vendor Name"]}
            resp = es.index(index="mac-vendors", doc_type="_doc", id=h, body=g)
            print(f"Indexed {h}: {resp}")

    # Split data into batches
    for i in range(0, len(data), batch_size):
        batch = data[i:i + batch_size]
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            executor.map(index_batch, [batch])

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
    print(f"Vendor Name for MAC Prefix 00-D0-EF: {resp['hits']['hits'][0]['_source']['Vendor Name']}")

def refresh_index(es):
    es.indices.refresh(index="mac-vendors")

def get_doc(es):
    resp = es.get(index="mac-vendors", id="D8:97:90")
    print(f"Data for ID D8:97:90: {resp['_source']}")

def main():
    AWS_EC2 = "https://saflu608fd:hn4wq7ssu4@testing-6258629515.us-east-1.bonsaisearch.net:443"
    es = Elasticsearch(AWS_EC2, verify_certs=False)

    # Create the index
    es.indices.create(index="mac-vendors")

    # Read data from vendor.json
    with open("vendor.json", encoding='utf-8-sig') as f:
        data = json.load(f)
    
    # Index document
    index_doc(es,data)

    # Refresh the index
    refresh_index(es)

    # Search for a specific MAC prefix
    # search(es)

    # Get a document by ID
    # get_doc(es)
    
    # REDO SETUP
    # es.indices.delete(index='mac-vendors')

if __name__ == "__main__":
    main()
