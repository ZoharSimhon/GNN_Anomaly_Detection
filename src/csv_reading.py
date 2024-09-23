import csv

from ann import ann_algorithm
from tri_graph import TriGraph
from clustering import check_all_anomalies, clustering_algorithm
from network import ANN
from combined_algo import check_anomalies
from results import measure_results
from visualization import plot_embeddings
from visualization import plot_embeddings

def replace_headers(pcap_file_path):
    # Old and new headers
    old_headers = ['IPV4_SRC_ADDR', 'L4_SRC_PORT', 'IPV4_DST_ADDR', 'L4_DST_PORT', 'PROTOCOL', 'L7_PROTO', 
                   'IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS', 'TCP_FLAGS', 'FLOW_DURATION_MILLISECONDS', 
                   'Label', 'Attack']
    
    new_headers = ['Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'L7_PROTO', 
                   'Total Length of Bwd Packets', 'Total Length of Fwd Packets', 'Total Bwd Packets', 
                   'Total Fwd Packets', 'TCP_FLAGS', 'FLOW_DURATION_MILLISECONDS', 'Label', 'Attack']

    # Read and modify the CSV headers
    with open(pcap_file_path, 'r') as infile:
        # Load the entire CSV into memory
        reader = list(csv.DictReader(infile))

    # Overwrite the same file with updated headers
    with open(f'{pcap_file_path}_new', 'w', newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=new_headers)
        writer.writeheader()
        for row in reader:
            new_row = {new_headers[i]: row[old_headers[i]] for i in range(len(old_headers))}
            writer.writerow(new_row)

def run_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=-1, algo='clustering', plot=False, replace=True):
    # Call the function to replace headers before processing
    if replace:
        replace_headers(pcap_file_path)
    
    if algo == 'network':
        ann = ANN()
    elif algo in ['ann', 'clustering', 'combined']:
        tri_graph = TriGraph(sliding_window_size)
        
    with open(f'{pcap_file_path}_new', mode='r') as file:
        csv_reader = csv.DictReader(file)
        pred = []
        label = []
        node_to_index = {}
        
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
            
            tri_graph.add_nodes_edges_csv(row, pred, label, node_to_index, not replace)
            
            # Compute the embeddings and the ANN every 100 flows
            if i and i % 2000== 0:
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
                
    measure_results(pred, label)

            
        
run_algo("../data/cic-ids-2018_separated/ftp.csv", plot=False)
