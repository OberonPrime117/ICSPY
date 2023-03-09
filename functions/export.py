import os
from elasticsearch import Elasticsearch 
import csv
import plotly.graph_objects as go
from dotenv import dotenv_values
import time
import multiprocessing

def visualise(img_static, csvfile):
    labels = []
    values = []

    if os.path.isfile(csvfile):

        with open(csvfile, 'r') as csvf:

            lines = csv.reader(csvf, delimiter = ',')

            for row in lines:
                labels.append(row[0])
                values.append(int(row[1]))

        fig = go.Figure(data=[go.Pie(labels=labels, values=values, pull=[0.1, 0.1, 0.2, 0.1])])
        fig.write_image(img_static)

def search(csvfile,test):
    config = dotenv_values(".env")
    ELASTIC_PASSWORD = config['ELASTIC_PASSWORD']
    es =  Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))

    searchp = { 
        "match_all" : {}
    }
    #print(test)
    
    resp = es.search(index=test, query=searchp)
    print(resp)
    #print(resp)
    
    #start = time.process_time()

    for j in resp["hits"]["hits"]:
        print(j)
        impact = es.get(index=test,id=j["_id"])

        b = []
        #print(impact["_id"])
        #print(csvfile)
        b.append(impact["_id"])
        b.append(impact["_source"]["Number of Packets"])

        if os.path.isfile(csvfile):
            with open(csvfile, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(b)
        else:
            with open(csvfile, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(b)

def export_data(img_static,csvfile,test):
    p1 = multiprocessing.Process(target=search , args=(csvfile,test))
    p1.start()
    p5 = multiprocessing.Process(target=visualise , args=(img_static,csvfile))
    p5.start()
    
    p1.join()
    p5.join()
    #print(time.process_time() - start)