# For graph representation
import networkx as nx
import matplotlib.pyplot as plt
from pyshark import FileCapture
from time import time
from queue import Queue

# For embeddings
import torch
import torch.nn as nn
import torch.optim as optim
from torch_geometric.nn import GCNConv
import torch.nn.functional as F

# For ANN
import numpy as np
from annoy import AnnoyIndex

# Function to perform anomaly detection using an Approximate Nearest Neighbor (ANN) algorithm
def ann_algorithm(graph, embeddings):    
    # Initialize an Annoy index for nearest neighbor search
    dimension = 2  # Number of features in the vectors
    index = AnnoyIndex(dimension, 'euclidean')

    # Add vectors to the index
    for i, embedding in enumerate(embeddings):
        index.add_item(i, embedding)

    n_trees =  10  # Number of trees for the index
    search_k = -1  # -1 means use n_trees * n_trees
    num_neighbors = 4  # Number of neighbors to find 
    
    # Build the index
    index.build(n_trees)
    
    # Calculate distances to the nearest neighbors
    distances = [index.get_nns_by_item(i, num_neighbors, include_distances=True, search_k=search_k)[1] for i in range(embeddings.shape[0])]
    
    # Calculate anomaly scores
    anomaly_scores = np.mean(distances, axis=1)
    
    # Thresholding
    threshold = np.percentile(anomaly_scores,  95)  # Use the  95th percentile as a threshold
    anomalies = anomaly_scores > threshold
    
    # Print the anomalies nodes
    list_nodes = list(graph.nodes)
    for i, anomaly in enumerate(anomalies):
        if anomaly:
            anomaly_node_id = list_nodes[i]
            anomaly_node = graph.nodes[anomaly_node_id]
            amount = anomaly_node['amount']
            length = anomaly_node['length']
            time_delta = anomaly_node['time_delta']
            print(f'found anomaly in {anomaly_node_id}: amount: {amount}, length: {length}, time_delta: {time_delta}')
    return anomalies

# Define a Graph Convolutional Network (GCN) model for generating embeddings
class GCN(torch.nn.Module):
    def __init__(self, num_features, hidden_size, output_size):
        super().__init__()
        torch.manual_seed(1234567)
        self.conv1 = GCNConv(num_features, hidden_size)
        self.conv2 = GCNConv(hidden_size, output_size)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = x.relu()
        x = self.conv2(x, edge_index)
        return x

# Define a class to represent a vector of network traffic data
class Vector():
    def __init__(self, length, src, dst, stream_number) -> None:
        self.length = length
        self.amount = 1
        self.time_delta = 0.0
        self.src = src
        self.dst = dst
        self.finished = False
        self.stream_number = stream_number

    # Aggregate the features on existing stream
    def add_packet(self, length, time_delta):
        if self.finished:
            self.reset()
        self.amount += 1
        self.length += length
        new_time_delta = self.time_delta + float(time_delta)
        self.time_delta = round(new_time_delta, 3)
    
    def reset(self):
        self.length = 0
        self.amount = 0
        self.time_delta = 0.0
        self.finished = False
        
    def __str__(self) -> str:
        return f'length: {self.length}, amount: {self.amount}, time_delta: {self.time_delta}, src: {self.src}, dst: {self.dst}'
    def __len__(self) -> int:
        return self.amount

# Define a class to represent a tri-graph structure for network traffic analysis
class TriGraph():
    def __init__(self, sliding_window_size = 1000) -> None:
        self.ipToID = {}
        self.graph = nx.Graph()
        self.count_flows = 1
        self.q = Queue(maxsize=sliding_window_size)
    
    def graph_embedding(self):
        # Convert node features to PyTorch tensors
        node_features = torch.FloatTensor([list([self.graph.nodes[node]['amount']/self.graph.nodes[node]['flows'], 
                                                 self.graph.nodes[node]['length']/self.graph.nodes[node]['flows'], 
                                                 self.graph.nodes[node]['time_delta']/self.graph.nodes[node]['flows']]) 
                                           for node in self.graph.nodes])

        # Convert edges to PyTorch tensors
        node_to_index = {node: i for i, node in enumerate(self.graph.nodes())}
        edges = [(node_to_index[u], node_to_index[v]) for u, v in self.graph.edges()]

        # Convert the list of edges to a NumPy array
        edges_array = np.array(edges)

        # Convert the NumPy array to a PyTorch tensor
        edge_index = torch.tensor(edges_array, dtype=torch.long).t().contiguous()

        # Initialize the neural network
        num_features = len(node_features[0])
        hidden_size = 256
        output_size = 128
        
        model = GCN(num_features, hidden_size, output_size)
        model.eval()

        embeddings = model(node_features, edge_index)
                
        return embeddings

    # Generate id number for ip:port
    def getId(self, key):
        if key not in self.ipToID:
            self.ipToID[key] = f'{len(self.ipToID)}ip'
        return self.ipToID[key]

    def visualize_directed_graph(self):
        plt.clf()
     
        pos = nx.multipartite_layout(self.graph, subset_key="side")

        # Draw nodes
        node_colors = [self.graph.nodes[node]["color"] for node in self.graph.nodes]
        nx.draw_networkx_nodes(self.graph, pos, node_color=node_colors, node_size=700, node_shape='o')
        
        # Draw node features
        node_labels = {node: node for node in self.graph.nodes}
        nx.draw_networkx_labels(self.graph, pos, labels=node_labels, font_color="white", font_size= 8)

        # Draw edges
        nx.draw_networkx_edges(self.graph, pos, edge_color='gray', node_size=700)
        
        plt.ion()
        plt.show()
        plt.pause(0.1)

    def add_nodes_edges(self, vector: Vector):
        #  add nodes
        src_id, dst_id = self.getId(vector.src), self.getId(vector.dst)

        if not self.graph.has_node(src_id):
            self.graph.add_node(src_id, side = 'Client', amount = 0, length = 0, time_delta = 0.0, ip = vector.src, flows = 0, color = "lightskyblue")
                
        if not self.graph.has_node(dst_id):
            self.graph.add_node(dst_id, side = 'Server', amount = 0, length = 0, time_delta = 0.0, ip = vector.dst, sip = vector.src, flows = 0, color = "lightcoral")
        
        self.update_features(src_id, vector)
        self.update_features(dst_id, vector)
        
        flow_node = f'{vector.stream_number}_{self.count_flows}f'
        if not self.graph.has_node(flow_node):
            self.graph.add_node(flow_node, side = 'Flow', amount = vector.amount, 
                        length = vector.length, time_delta = vector.time_delta, flows = 1, color = "violet")
            
        # add edges
        if not self.graph.has_edge(src_id, flow_node):
            self.graph.add_edge(src_id, flow_node)
        if not self.graph.has_edge(flow_node, dst_id):
            self.graph.add_edge(flow_node, dst_id)
        
        # update count_flows
        self.count_flows += 1
        
        # update q (FIFO style)
        if self.q.full():
            index = self.q.get()
            neighbors = self.graph.neighbors(index)
            node_delete = [index]
            # Update all the entities (Server + Client) that connected to this flow
            for neighbor in neighbors:
                self.graph.nodes[neighbor]["flows"] -= 1
                if self.graph.nodes[neighbor]["flows"] == 0:
                    node_delete.append(neighbor)
           
            # Delete the last flow and isolated nodes from tri_graph
            for node in node_delete:
                self.graph.remove_node(node)
         
        self.q.put(flow_node)
            

    def update_features(self, id, vector):
        # Update features of a node in the graph
        self.graph.nodes[id]["amount"] += vector.amount  
        self.graph.nodes[id]["length"] += vector.length   
        self.graph.nodes[id]["time_delta"] +=  vector.time_delta
        self.graph.nodes[id]["flows"] += 1
        
# Plot the graph embeddings
def plot_embeddings(embeddings, anomalies):
    # Convert embeddings to a NumPy array
    embeddings_array = embeddings.squeeze()

    # Plot embeddings acordding to their anomaly score
    plt.clf()
    for i, embedding in enumerate(embeddings_array):
        if anomalies[i]: # The embedding is anomaly
            plt.scatter(embedding[0], embedding[1], c='lightcoral', alpha=0.5)
            plt.annotate(f"", (embedding[0], embedding[1]), textcoords="offset points", 
                         xytext=(5,5), ha='right')
        else:
            plt.scatter(embedding[0], embedding[1], c='lightskyblue', alpha=0.5)
            plt.annotate(f"", (embedding[0], embedding[1]), textcoords="offset points", 
                         xytext=(5,5), ha='right')
            
            


    plt.title("Graph Embeddings")
    plt.xlabel("Dimension 1")
    plt.ylabel("Dimension 2")
    plt.ion()
    plt.show()
    plt.pause(0.1)
    
# Run the algorithm on the given pcap file
def run_algo(pcap_file, sliding_window_size, num_of_rows=500):
    cap = FileCapture(pcap_file)
    tri_graph = TriGraph()
    prev_time = time(sliding_window_size)

    streams = {}
    
    for i, packet in enumerate(cap):
        if i == num_of_rows:
            return

        # Plot the graph every 2 seconds 
        if 2 <= time() - prev_time:
            tri_graph.visualize_directed_graph()
            prev_time = time()
        
        # Compute the embeddings and the ANN every 10 flows
        if tri_graph.count_flows % 10 == 0:
            embeddings = tri_graph.graph_embedding()
            embeddings = embeddings.detach().numpy()
            anomalies = ann_algorithm(tri_graph.graph,embeddings)
            plot_embeddings(embeddings, anomalies)

        # Check only TCP packets
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):

            # Skip retransmission packets
            if 'analysis_retransmission' in dir(packet.tcp):
                continue

            # Get the ip, port for the src and dst
            src_ip, dst_ip = packet.ip.src, packet.ip.dst
            dest_port = packet[packet.transport_layer].dstport if hasattr(
                packet, 'transport_layer') else None
            src_port = packet[packet.transport_layer].srcport if hasattr(
                packet, 'transport_layer') else None
            
            # Get the stream numner from the TCP packet
            stream_number = int(packet.tcp.stream)
            
            if stream_number not in streams: # Got a new flow number
                streams[stream_number] = Vector(len(packet), f'{src_ip}:{src_port}', f'{dst_ip}:{dest_port}', stream_number)
            else: # New packet of existing flow
                vector = streams[stream_number]
                #  Divide large flow into small portions
                if vector.time_delta > 0.1:
                    vector.finished = True
                    tri_graph.add_nodes_edges(vector)
                # Aggregate the packet's feature to the existing flow
                vector.add_packet(len(packet), packet.tcp.time_delta)

            vector = streams[stream_number]
            # End a flow in FYN or RST flag is opened
            if packet.tcp.flags_fin == 'True' or packet.tcp.flags_reset == 'True':
                # if the stream is only fin, ignore it
                if vector.amount == 1:
                    vector.reset()
                    continue
                
                # Add the whole flow - after he terminated to tri_graph
                tri_graph.add_nodes_edges(vector)
                streams.pop(stream_number)


if __name__ == '__main__':

    pcap_file_path = 'attack.pcap'
    run_algo(pcap_file_path, 1000, 50000)

