from elasticsearch import Elasticsearch
import json
import threading
from concurrent.futures import ThreadPoolExecutor

def index_doc(es, data, batch_size=15):
    def index_batch(batch):
        for b in batch:
            a = list(b.keys())
            h = a[0]
            g = {"Protocol Name": b[h]}
            resp = es.index(index="elasticproto", doc_type="_doc", id=h, body=g)
            print(f"Indexed {h}: {resp}")

    # Split data into batches
    for i in range(0, len(data), batch_size):
        batch = data[i:i + batch_size]
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            executor.map(index_batch, [batch])

def refresh_index(es):
    es.indices.refresh(index="elasticproto")

def main():
    AWS_EC2 = "https://saflu608fd:hn4wq7ssu4@testing-6258629515.us-east-1.bonsaisearch.net:443"
    es = Elasticsearch(AWS_EC2, verify_certs=False)

    # Create the index
    es.indices.create(index="elasticproto")

    # Read data from vendor.json
    with open("protocol.json", encoding='utf-8-sig') as f:
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
    # es.indices.delete(index='elasticproto')

if __name__ == "__main__":
    main()