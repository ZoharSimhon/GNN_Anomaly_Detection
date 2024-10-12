import csv

from ann import ann_algorithm
from tri_graph import TriGraph
from clustering import check_all_anomalies, clustering_algorithm
from network import ANN
from combined_algo import check_anomalies
from results import measure_results
from visualization import plot_embeddings

def run_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=5000, algo='clustering', plot=False):
    if algo == 'network':
        ann = ANN()
    elif algo in ['ann', 'clustering', 'combined']:
        tri_graph = TriGraph(sliding_window_size)
        
    with open(pcap_file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)
        pred = []
        label = []
        node_to_index = {}

        current_batch_new_nodes = 0

        # Iterate through each line in the CSV
        for i, row in enumerate(csv_reader):
            if i == num_of_rows:
                break
            
            # Strip spaces from keys and replace 'Backward' with 'Bwd'
            row = {key.strip().replace('Backward', 'Bwd'): value for key, value in row.items()}

            if algo == 'network':
                break
            
            if row['Protocol'] != '6':
                continue
            
            tri_graph.add_nodes_edges_csv(row, pred, label, node_to_index)
    
            # Compute the embeddings and clustering every x flows
            if i and i % 50 == 0:
                print(f'{current_batch_new_nodes} - {len(pred) - 1}')
                # print(tri_graph.graph.nodes)
                embeddings = tri_graph.create_embeddings()
                current_batch_embeddings = embeddings[current_batch_new_nodes:len(pred)]
                current_batch_new_nodes = len(pred)
                if algo == 'ann' or algo == 'combined':
                    anomalies = ann_algorithm(tri_graph.graph, embeddings.detach().numpy(), algo != 'combined')
                if algo == 'clustering' or algo == 'combined':
                    cluster_embeddings = current_batch_embeddings.detach().numpy()
                    clusters = clustering_algorithm(cluster_embeddings)
                    check_all_anomalies(tri_graph.graph, cluster_embeddings, clusters, False, pred, node_to_index)
                if algo == 'combined':
                    check_anomalies(tri_graph.graph)

                if plot:
                    tri_graph.visualize_directed_graph()
                    plot_embeddings(embeddings, tri_graph.graph)
                print(f'processed {i} flows')
                
        measure_results(pred, label)

            
        
run_algo("../data/2017csv/ftp.csv", plot=False)
