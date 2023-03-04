import networkx as nx
import igviz as ig

G = nx.random_geometric_graph(200, 0.125)
nx.set_node_attributes(G, 3, "prop")
nx.set_edge_attributes(G, 5, "edge_prop")

ig.plot(
    G,
    title="My Graph",
    size_method="prop", # Makes node sizes the size of the "prop" property
    color_method="prop", # Colors the nodes based off the "prop" property and a color scale,
    node_text=["prop"], # Adds the 'prop' property to the hover text of the node
)