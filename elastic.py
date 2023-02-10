from datetime import datetime
from elasticsearch import Elasticsearch
ELASTIC_PASSWORD = "-jnEVq4pt66m9GDJpxQy"
es = Elasticsearch("http://localhost:9200",basic_auth=("elastic", ELASTIC_PASSWORD))
print(es.info().body)