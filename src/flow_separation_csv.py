import csv
import numpy as np

from ann import ann_algorithm
from vector import Vector
from tri_graph import TriGraph
from visualization import plot_embeddings, plot_ann_indexes
from clustering import check_all_anomalies, clustering_algorithm
from network import ANN
from combined_algo import check_anomalies
from results import measure_results

def update_flow_state(flow, row):
    fin_flag = row['tcp.flags.fin'] == '1'
    ack_flag = row['tcp.flags.ack'] == '1'

    current_state = flow.state

    if current_state == 'ESTABLISHED':
        if fin_flag:
            flow.state = 'FIN_WAIT'
    
    elif current_state == 'FIN_WAIT':
        if ack_flag and fin_flag:
            flow.state = 'CLOSE_WAIT'
        elif ack_flag:
            flow.state = 'FIN_WAIT_ACKED'
    
    elif current_state == 'FIN_WAIT_ACKED':
        if fin_flag:
            flow.state = 'CLOSE_WAIT'
    
    elif current_state == 'CLOSE_WAIT':
        if ack_flag:
            flow.state = 'CLOSED'

    if row['tcp.flags.reset'] == '1':
        flow.state = 'CLOSED'

def find_packet_time(row):
    ts = int(float(row['frame.time_epoch']))
    return ts
    # return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def run_csv_algo(pcap_file, sliding_window_size, num_of_rows=-1, algo='ann', plot=True):
    
    if algo == 'network':
        ann = ANN()
    elif algo in ['ann', 'clustering', 'combined']:
        tri_graph = TriGraph(sliding_window_size)
    
    def flow_finished(vector):
        if algo == 'network' and ann.add_vector(vector)[0] == 'anomaly':
            print(f'anomaly on index {i}, stream: {stream_number}, vector: {vector}\n')
        elif algo in ['ann', 'clustering', 'combined']:
            tri_graph.add_nodes_edges(vector)
    
    with open(pcap_file, mode='r') as file:
        csv_reader = csv.DictReader(file)
        
        prev_count_flows = 0

        streams = {}
        # Iterate through each line in the CSV
        for i, row in enumerate(csv_reader):
            
            if i == num_of_rows:
                break
            
            if i % 10000 == 0:
                print(f'processed {i} packets')
                
            # Check only TCP packets
            if row['ip.proto'] != '6':
                continue

            # if row['tcp.stream'] != '5':
            #     continue

            # Get the ip, port for the src and dst
            src_ip, dst_ip = row['ip.src'], row['ip.dst']
            src_port, dest_port = row['tcp.srcport'], row['tcp.dstport']
            
            # Get the stream numner from the TCP packet
            stream_number = int(row['tcp.stream'])

            flags = {
                'FIN': int(row['tcp.flags.fin']),
                'SYN': int(row['tcp.flags.syn']),
                'RST': int(row['tcp.flags.reset']),
                'PSH': int(row['tcp.flags.push']),
                'ACK': int(row['tcp.flags.ack']),
                'URG': int(row['tcp.flags.urg']),
            }
            
            if int(src_port) > int(dest_port):
                src, dst, fwd = f'{src_ip}:{src_port}', f'{dst_ip}:{dest_port}', True
            else:
                dst, src, fwd = f'{src_ip}:{src_port}', f'{dst_ip}:{dest_port}', False
            
            if stream_number not in streams: # Got a new flow number
                # Skip single resets packets
                if row['tcp.flags.reset'] == '1':
                    continue
                
                streams[stream_number] = Vector(int(row['frame.len']), src, dst, fwd, stream_number, flags)
            else: # New packet of existing flow
                vector = streams[stream_number]
                #  Divide large flow into small portions
                # print(find_packet_time(row) - vector.packet_index)
                # if find_packet_time(row) - vector.packet_index > 2:
                #     vector.finished = True
                #     vector.packet_index = find_packet_time(row)
                #     flow_finished(vector)
                # Aggregate the packet's feature to the existing flow
                vector.add_packet(int(row['frame.len']), row['tcp.time_delta'], src, flags)

            vector = streams[stream_number]
            update_flow_state(vector, row)
            # End a flow in FYN or RST flag is opened
            if vector.state == 'CLOSED':
                # Add the whole flow - after he terminated to tri_graph
                vector.packet_index = find_packet_time(row)
                flow_finished(vector)
                streams.pop(stream_number)
            
            if algo == 'network':
                if plot:
                    # create_plot(streams.values())
                    plot_ann_indexes(np.array(ann.vectors))
                continue

            # Compute the embeddings and the ANN every X flows
            if tri_graph.count_flows - prev_count_flows >= 2000:
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
                # tri_graph = TriGraph()
                if plot:
                    tri_graph.visualize_directed_graph()
                    plot_embeddings(embeddings, tri_graph.graph)
                prev_count_flows = tri_graph.count_flows
    
    measure_results(tri_graph.graph)
