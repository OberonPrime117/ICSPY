# load data
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
df = pd.read_csv("data/book1.csv")
# pick only important weights (hard threshold)
df = df.loc[df['weight']>10, :]
# import
import networkx as nx
# load pandas df as networkx graph
G = nx.from_pandas_edgelist(df, 
                            source='Source', 
                            target='Target', 
                            edge_attr='weight')
print("No of unique characters:", len(G.nodes))
print("No of connections:", len(G.edges))
# import pyvis
from pyvis.network import Network
# create vis network
net = Network(notebook=True, width=1000, height=600)
# load the networkx graph
net.from_nx(G)
# show
net.show("example.html")