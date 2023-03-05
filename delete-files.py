import os
from elasticsearch import Elasticsearch

def delete(filename):
    try:
        os.remove(filename)
    except:
        pass

delete("static/dst-ip.png")
delete("static/dst-port.png")
delete("static/protocol.png")
delete("static/src-ip.png")
delete("static/src-port.png")
delete("static/vendor.png")
delete("results/pair-of-ip.csv")
delete("results/dst-ip.csv")
delete("results/dst-port.csv")
delete("results/protocol.csv")
delete("results/src-ip.csv")
delete("results/src-port.csv")
delete("results/vendor.csv")

ELASTIC_PASSWORD = "M_R*tu-=C_98N2GZDoT_"
es =  Elasticsearch(["https://localhost:9200"],basic_auth=("elastic", ELASTIC_PASSWORD),verify_certs=True ,ca_certs="http_ca.crt")
es.options(ignore_status=[400,404]).indices.delete(index='srcdst')
es.options(ignore_status=[400,404]).indices.delete(index='srcip')
es.options(ignore_status=[400,404]).indices.delete(index='dstip')
es.options(ignore_status=[400,404]).indices.delete(index='vendors')
es.options(ignore_status=[400,404]).indices.delete(index='protocol')
es.options(ignore_status=[400,404]).indices.delete(index='srcport')
es.options(ignore_status=[400,404]).indices.delete(index='dstport')