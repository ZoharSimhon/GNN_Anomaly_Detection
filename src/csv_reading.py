import csv

from ann import ann_algorithm
from tri_graph import TriGraph
from clustering import check_all_anomalies, clustering_algorithm
from network import ANN
from combined_algo import check_anomalies
from results import measure_results


def run_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=-1, algo='clustering'):
    if algo == 'network':
        ann = ANN()
    elif algo in ['ann', 'clustering', 'combined']:
        tri_graph = TriGraph(sliding_window_size)
        
    with open(pcap_file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)
        
        # Iterate through each line in the CSV
        for i, row in enumerate(csv_reader):
            if i == num_of_rows:
                break
            if i % 10000 == 0:
                print(f'processed {i} flows')
            
            # Strip spaces from keys and replace 'Backward' with 'Bwd'
            row = {key.strip().replace('Backward', 'Bwd'): value for key, value in row.items()}

            if algo == 'network':
                continue
            
            if row['Protocol'] != '6':
                continue
            
            tri_graph.add_nodes_edges_csv(row)
            
            # Compute the embeddings and the ANN every 100 flows
            if i and i % 2000 == 0:
                print("Checking anomalies...")
                embeddings = tri_graph.create_embeddings()
                if algo == 'ann' or algo == 'combined':
                    anomalies = ann_algorithm(tri_graph.graph, embeddings.detach().numpy(), algo != 'combined')
                if algo == 'clustering' or algo == 'combined':
                    cluster_embeddings = embeddings.detach().numpy()
                    clusters = clustering_algorithm(cluster_embeddings)
                    check_all_anomalies(tri_graph.graph, cluster_embeddings, clusters, algo != 'combined')
                if algo == 'combined':
                    check_anomalies(tri_graph.graph)
        
        measure_results(tri_graph.graph)

            
        
run_algo("..\\data\\Wednesday-dos.pcap_ISCX.csv")