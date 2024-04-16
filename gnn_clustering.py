# For graph representation
import networkx as nx
import matplotlib.pyplot as plt
from pyshark import FileCapture
from time import time
from queue import Queue
import numpy as np

# For embeddings
import torch
from torch_geometric.nn import GCNConv

# For clustering
import hdbscan

# For anomalies
from sklearn.metrics import pairwise_distances_argmin_min


# Function to perform clustering algorithm
def clustering_algorithm(graph, embeddings): 
    
    # Initialize HDBSCAN
    clusterer = hdbscan.HDBSCAN(min_cluster_size=5, gen_min_span_tree=True)
    
    # Perform clustering
    cluster_labels = clusterer.fit_predict(embeddings)
    
    return cluster_labels

#Function to calculte the amount of every cluster
def count_vectors_in_clusters(labels):
    unique_labels, counts = np.unique(labels, return_counts=True)
    cluster_counts = dict(zip(unique_labels, counts))
    return cluster_counts

# Function to measure distance of a cluster
def find_centroids(vectors, labels):
    # Calculate centroids for each cluster
    centroids = []
    for cluster in np.unique(labels):
        cluster_points = vectors[labels == cluster]
        centroid = np.mean(cluster_points, axis=0)
        centroids.append(centroid)
    
    # Convert centroids to a NumPy array
    return np.array(centroids)

def calculate_centroid_distances(centroids):
    distances = []
    for i in range(len(centroids)):
        list_without_current = np.delete(centroids, i, axis=0)
        current_distance = pairwise_distances_argmin_min(centroids, list_without_current, metric='euclidean')[1]
        distances.append(current_distance[i])
    return distances

# Function to measure density of a cluster
def calculate_density(vectors, labels):
    densities = []
    for cluster in np.unique(labels):
        cluster_points = vectors[labels == cluster]
        centroid = np.mean(cluster_points, axis=0)
        distances = pairwise_distances_argmin_min(cluster_points, [centroid])[1]
        current_density = np.mean(distances)
        densities.append(current_density)
    return densities

def check_anomalies(elements, threshold=1.5):
    avg_distance = np.mean(elements)
    std_distance = np.std(elements)
    
    unusual_distances = [i for i in range(len(elements)) 
                        if (elements[i] > avg_distance + threshold * std_distance) 
                        or  (elements[i] < avg_distance - threshold * std_distance)]
    
    return unusual_distances

def check_all_anomalies(embeddings, clusters):
    # Count the number of vectors in each cluster
    cluster_counts = count_vectors_in_clusters(clusters)
    
    # Check for anomaly clusters count
    unusual_clusters = check_anomalies(list(cluster_counts.values()))
    if unusual_clusters:
        print("Number of vectors in each cluster:", cluster_counts)
        print("Unusual clusters (amount):", unusual_clusters)
        print()
        
    
    # Calculate densities in each cluster
    cluster_densities = calculate_density(embeddings, clusters)
    
    # Check for anomaly clusters
    unusual_clusters = check_anomalies(cluster_densities)
    if unusual_clusters:
        print("Densities in each cluster:", cluster_densities)
        print("Unusual clusters (density):", unusual_clusters)
        print()
        
    # Calculate distances between centroids
    centroids = find_centroids(embeddings, clusters)
    centroid_distances = calculate_centroid_distances(centroids)
    
    # Check for anomaly distances
    unusual_distances = check_anomalies(centroid_distances)
    if unusual_distances:
        print("Distances between centroids:", centroid_distances)
        print("Unusual distances:", unusual_distances)
        print()
        
    print()
    print()
    

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
        features = [list([self.graph.nodes[node]['amount']/self.graph.nodes[node]['flows'], 
                                                 self.graph.nodes[node]['length']/self.graph.nodes[node]['flows'], 
                                                 self.graph.nodes[node]['time_delta']/self.graph.nodes[node]['flows']]) 
                                           for node in self.graph.nodes]
        node_features = torch.FloatTensor(features)

        # Convert edges to PyTorch tensors
        node_to_index = {node: i for i, node in enumerate(self.graph.nodes())}
        edges = [(node_to_index[u], node_to_index[v]) for u, v in self.graph.edges()]

        # Convert the list of edges to a NumPy array
        edges_array = np.array(edges)

        # Convert the NumPy array to a PyTorch tensor
        edge_index = torch.tensor(edges_array, dtype=torch.long).t().contiguous()

        # Initialize the neural network
        num_features = len(node_features[0])
        hidden_size = 8
        output_size = 2
        
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
        plt.pause(0.15)

    def add_nodes_edges(self, vector: Vector):
        # add nodes
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
def plot_embeddings(embeddings, clusters):
    # Convert embeddings to a NumPy array
    # embeddings_array = embeddings.squeeze()
    embeddings_array = embeddings
            
    plt.scatter(embeddings_array[:, 0], embeddings_array[:, 1], c=clusters, alpha=0.5)
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
    prev_time = time()
    prev_count_flows = 0

    streams = {}
    
    for i, packet in enumerate(cap):
        if i == num_of_rows:
            return

        # Plot the graph every 2 seconds 
        if 2 <= time() - prev_time:
            tri_graph.visualize_directed_graph()
            prev_time = time()
        
        # Compute the embeddings and the ANN every 10 flows
        if tri_graph.count_flows - prev_count_flows >= 10:
            embeddings = tri_graph.graph_embedding()
            embeddings = embeddings.detach().numpy()
            clusters = clustering_algorithm(tri_graph.graph,embeddings)
            check_all_anomalies(embeddings, clusters)
            plot_embeddings(embeddings, clusters)
            prev_count_flows = tri_graph.count_flows

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
            if packet.tcp.flags_fin == '1' or packet.tcp.flags_reset == '1':
                # if the stream is only fin, ignore it
                if vector.amount == 1:
                    vector.reset()
                    continue
                
                # Add the whole flow - after he terminated to tri_graph
                tri_graph.add_nodes_edges(vector)
                streams.pop(stream_number)


if __name__ == '__main__':

    pcap_file_path = '081523-1308_1640.pcap'
    run_algo(pcap_file_path, 1000, 50000)

