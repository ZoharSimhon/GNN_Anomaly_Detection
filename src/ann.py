import numpy as np
from annoy import AnnoyIndex

def print_node(node) -> str:
    amount = node['amount']
    length = node['length']
    time_delta = node['time_delta']
    side = node['side']

    print_str= f'amount: {amount}, length: {length}, time_delta: {time_delta}'
    if side == 'Client':
        ip = node['ip']
        print_str += f'\n on Client ip: {ip} \n'
    
    elif side == 'Server':
        ip = node['ip']
        print_str += f'\n on Server ip: {ip} \n'

    else: # side = 'Flow
        stream_number = node['stream_number']
        sip = node['sip']
        dip = node['dip']
        
        print_str += f'\n on Flow number: {stream_number} with Client ip: {sip} and Server ip: {dip} \n'
    
    return print_str

# Function to perform anomaly detection using an Approximate Nearest Neighbor (ANN) algorithm
def ann_algorithm(graph, embeddings):    
    # Initialize an Annoy index for nearest neighbor search
    dimension = 32  # Number of features in the vectors
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
    # threshold = np.percentile(anomaly_scores, 99.99)  # Use the  95th percentile as a threshold
    # anomalies = anomaly_scores > threshold
    
    avg_distance = np.mean(anomaly_scores)
    std_distance = np.std(anomaly_scores)
    threshold = 5
    
    anomalies = [i for i in range(len(anomaly_scores)) 
                        if (anomaly_scores[i] > avg_distance + threshold * std_distance) ]
    
    # Print the anomalies nodes
    list_nodes = list(graph.nodes)
    for i, anomaly in enumerate(anomalies):
        if anomaly:
            anomaly_node_id = list_nodes[i]
            anomaly_node = graph.nodes[anomaly_node_id]
            anomaly_node_str = print_node(anomaly_node)
            print(f'found anomaly on packet number {anomaly_node["packet_index"]} (node id: {anomaly_node_id}): {anomaly_node_str}')
            
    return anomalies
