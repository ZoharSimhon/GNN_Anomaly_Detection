import csv
import sys

from ann import ann_algorithm
from tri_graph import TriGraph
from clustering import check_all_anomalies, clustering_algorithm
from network import ANN
from combined_algo import check_anomalies
from results import measure_results
from visualization import plot_embeddings
from visualization import plot_embeddings

feature_to_name_IoT = {
    'Source IP': 'Src IP',
    'Source Port': 'Src Port',
    'Destination IP': 'Dst IP',
    'Destination Port': 'Dst Port',
    'amount_Fwd': 'Tot Fwd Pkts',
    'amount_Bwd': 'Tot Bwd Pkts',
    'length_Fwd': 'TotLen Fwd Pkts',
    'length_Bwd': 'TotLen Bwd Pkts',
    'min_packet_length_Fwd': 'Fwd Pkt Len Min',
    'min_packet_length_Bwd': 'Bwd Pkt Len Min',
    'max_packet_length_Fwd': 'Fwd Pkt Len Max',
    'max_packet_length_Bwd': 'Bwd Pkt Len Max',
    'Timestamp': 'Timestamp',
    'FIN': 'FIN Flag Cnt', 
    'SYN': 'SYN Flag Cnt',
    'RST': 'RST Flag Cnt',
    'PSH': 'PSH Flag Cnt',
    'ACK': 'ACK Flag Cnt',
    'URG': 'URG Flag Cnt',
    'Protocol': 'Protocol',
}

feature_to_name_CIC_2017 = {
    'Source IP': ' Source IP',
    'Source Port': ' Source Port',
    'Destination IP': ' Destination IP',
    'Destination Port': ' Destination Port',
    'amount_Fwd': ' Total Fwd Packets',
    'amount_Bwd': ' Total Backward Packets',
    'length_Fwd': ' Total Length of Bwd Packets',
    'length_Bwd': ' Total Length of Bwd Packets',
    'min_packet_length_Fwd': ' Fwd Packet Length Min',
    'min_packet_length_Bwd': ' Bwd Packet Length Min',
    'max_packet_length_Fwd': ' Fwd Packet Length Max',
    'max_packet_length_Bwd': 'Bwd Packet Length Max',
    'Timestamp': ' Timestamp',
    'FIN': 'FIN Flag Count', 
    'SYN': ' SYN Flag Count',
    'RST': ' RST Flag Count',
    'PSH': ' PSH Flag Count',
    'ACK': ' ACK Flag Count',
    'URG': ' URG Flag Count',
    'Protocol': ' Protocol',
}


def run_algo(dic_feature_to_name, pcap_file_path=None, num_of_flows=None, sliding_window_size=1000, num_of_rows=-1, algo='clustering', plot=False):
    # If no pcap_file_path is provided, check for command-line argument
    if pcap_file_path is None:
        pcap_file_path = sys.argv[1]
    # If no num_of_flows is provided, check for command-line argument
    if num_of_flows is None:
        if len(sys.argv) < 3 or not sys.argv[2].isdecimal() or int(sys.argv[2]) <= 0:
            num_of_flows = 2000
        else:
            num_of_flows = int(sys.argv[2])
                
    if algo == 'network':
        ann = ANN()
    elif algo in ['ann', 'clustering', 'combined']:
        tri_graph = TriGraph(sliding_window_size)
        
    with open(pcap_file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)
        pred = []
        label = []
        node_to_index = {}
        
        # Iterate through each line in the CSV
        for i, row in enumerate(csv_reader):
            if i % 10000 == 0:
                print(f'processed {i} flows')
            
            if algo == 'network':
                continue
            
            if row[dic_feature_to_name['Protocol']] != '6':
                continue
            
            tri_graph.add_nodes_edges_csv(row, pred, label, node_to_index, dic_feature_to_name)
            # Compute the embeddings and the ANN every 100 flows
            if (i and i % num_of_flows== 0) or (i >= num_of_rows):
                print("Checking anomalies...")
                embeddings = tri_graph.create_embeddings()
                if algo == 'ann' or algo == 'combined':
                    anomalies = ann_algorithm(tri_graph.graph, embeddings.detach().numpy(), algo != 'combined')
                if algo == 'clustering' or algo == 'combined':
                    cluster_embeddings = embeddings.detach().numpy()
                    clusters = clustering_algorithm(cluster_embeddings)
                    check_all_anomalies(tri_graph.graph, cluster_embeddings, clusters, algo != 'combined', pred, node_to_index)
                if algo == 'combined':
                    check_anomalies(tri_graph.graph)

                if plot:
                    tri_graph.visualize_directed_graph()
                    plot_embeddings(embeddings, tri_graph.graph)
                # tri_graph.graph.clear()
                
            if i >= num_of_rows:
                break
                
        print("Checking anomalies...")
        embeddings = tri_graph.create_embeddings()
        if algo == 'ann' or algo == 'combined':
            anomalies = ann_algorithm(tri_graph.graph, embeddings.detach().numpy(), algo != 'combined')
        if algo == 'clustering' or algo == 'combined':
            cluster_embeddings = embeddings.detach().numpy()
            clusters = clustering_algorithm(cluster_embeddings)
            check_all_anomalies(tri_graph.graph, cluster_embeddings, clusters, algo != 'combined', pred, node_to_index)
        if algo == 'combined':
            check_anomalies(tri_graph.graph)

        if plot:
            tri_graph.visualize_directed_graph()
            plot_embeddings(embeddings, tri_graph.graph)
        # tri_graph.graph.clear()
                
        measure_results(tri_graph.graph)

            
        
# run_algo("../data/cic-ids-2017-seperated/Thursday-XSS.pcap_ISCX.csv", feature_to_name_CIC_2017 ,plot=False)
run_algo(feature_to_name_IoT ,plot=False, num_of_rows=800000)
