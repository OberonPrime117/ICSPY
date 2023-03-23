import networkx as nx
from pyvis.network import Network
import pandas as pd
df = pd.read_csv('results/src-dst.csv')
G = nx.from_pandas_edgelist( df, source='Source', target='Destination', edge_attr=True)
net = Network(notebook=True)
net.from_nx(G)
net.show("templates/network-graph.html")