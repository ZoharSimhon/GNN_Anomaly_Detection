import matplotlib.pyplot as plt
import networkx as nx
from sklearn.manifold import TSNE

def visualize_directed_graph(self):
        plt.clf()

        # Get the nodes for each subset
        left_nodes = [node for node in self.graph.nodes if self.graph.nodes[node]["side"] == "Client"]
        middle_nodes = [node for node in self.graph.nodes if self.graph.nodes[node]["side"] == "Flow"]
        right_nodes = [node for node in self.graph.nodes if self.graph.nodes[node]["side"] == "Server"]
        
        # Initialize positions dictionary
        pos = {}
        
        # Set positions for left nodes
        for i, node in enumerate(left_nodes):
            pos[node] = (-1, i * 2.0 / len(left_nodes))  # Adjust the multiplier for better spacing
        
        # Set positions for middle nodes
        for i, node in enumerate(middle_nodes):
            pos[node] = (0, i * 2.0 / len(middle_nodes))
        
        # Set positions for right nodes
        for i, node in enumerate(right_nodes):
            pos[node] = (1, i * 2.0 / len(right_nodes))
        
        # Draw nodes
        node_colors = [self.graph.nodes[node]["color"] for node in self.graph.nodes]
        nx.draw_networkx_nodes(self.graph, pos, node_color=node_colors, node_size=400, node_shape='o')
        
        # Draw node labels
        node_labels = {node: node for node in self.graph.nodes}
        nx.draw_networkx_labels(self.graph, pos, labels=node_labels, font_color="white", font_size=6, verticalalignment='center')
        
        # Draw edges
        nx.draw_networkx_edges(self.graph, pos, edge_color='gray', node_size=700)
        
        plt.ion()
        plt.show()
        plt.pause(0.1)

# Plot the graph embeddings
def plot_embeddings(embeddings, graph: nx.graph):
    # Convert embeddings to a NumPy array
    perplexity = 5
    embeddings_array = TSNE(n_components=2, perplexity=perplexity).fit_transform(embeddings.detach().cpu().numpy())
    
    # Prepare the plot
    plt.clf()
    ids = list(graph.nodes)
    
    # Create a dictionary to map colors to labels
    color_label_map = {}
    for id in ids:
        if graph.nodes[id]["side"] == "Client":
            color = graph.nodes[id]["color"]
            label = graph.nodes[id]["ip"].split(":")[0]
            if color not in color_label_map:
                color_label_map[color] = label
    
    # Plot embeddings according to their anomaly score
    for i, embedding in enumerate(embeddings_array):
        id = ids[i]
        if graph.nodes[id]["side"] != "Client":
            continue
        plt.scatter(embedding[0], embedding[1], c=graph.nodes[id]["color"], alpha=0.5, label=graph.nodes[id]["ip"].split(":")[0])

    # Create the legend
    handles = [plt.Line2D([0], [0], marker='o', color='w', markerfacecolor=color, markersize=10) for color in color_label_map]
    labels = [label for label in color_label_map.values()]
    # plt.legend(handles, labels, title="Legend", loc='best')
    plt.legend(handles, labels, loc='best')
    
    # Finalize the plot
    plt.title("Graph Embeddings")
    plt.xlabel("Dimension 1")
    plt.ylabel("Dimension 2")
    plt.ion()
    plt.show()
    plt.pause(0.1)
    
