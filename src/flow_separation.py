from pyshark import FileCapture
from time import time
from datetime import datetime
import numpy as np

from ann import ann_algorithm
from vector import Vector
from tri_graph import TriGraph
from visualization import plot_embeddings, plot_ann_indexes
from clustering import check_all_anomalies, clustering_algorithm
from network import ANN
    
def update_flow_state(flow, packet):
    fin_flag = packet.tcp.flags_fin == '1'
    ack_flag = packet.tcp.flags_ack == '1'
    
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

    if packet.tcp.flags_reset == '1':
        flow.state = 'CLOSED'

def find_packet_time(packet):
    ts = int(float(packet.frame_info.time_epoch))
    return ts
    # return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')


def run_algo(pcap_file, sliding_window_size, num_of_rows=-1, algo='ann', plot=True):
    
    if algo == 'network':
        ann = ANN()
    elif algo in ['ann', 'clustering']:
        tri_graph = TriGraph(sliding_window_size)
    
    def flow_finished(vector):
        if algo == 'network' and ann.add_vector(vector)[0] == 'anomaly':
            print(f'anomaly on index {i}, stream: {stream_number}, vector: {vector}\n')
        elif algo in ['ann', 'clustering']:
            tri_graph.add_nodes_edges(vector)
    
    cap = FileCapture(pcap_file)
    prev_time = time()
    prev_count_flows = 0

    streams = {}
    
    for i, packet in enumerate(cap):
        if i == num_of_rows:
            return
        
        if i % 10000 == 0:
            print(f'processed {i} packets')
            
        # Plot the graph every 2 seconds 
        if 2 <= time() - prev_time and plot:
            if algo == 'network':
                # create_plot(streams.values())
                plot_ann_indexes(np.array(ann.vectors))
            elif algo in ['ann', 'clusting']:
                tri_graph.visualize_directed_graph()
            prev_time = time()
            
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

            flags = {
                'FIN': int(packet.tcp.flags_fin),
                'SYN': int(packet.tcp.flags_syn),
                'RST': int(packet.tcp.flags_reset),
                'PSH': int(packet.tcp.flags_push),
                'ACK': int(packet.tcp.flags_ack),
                'URG': int(packet.tcp.flags_urg),
            }
            
            if int(src_port) > int(dest_port):
                src, dst, fwd = f'{src_ip}:{src_port}', f'{dst_ip}:{dest_port}', True
            else:
                dst, src, fwd = f'{src_ip}:{src_port}', f'{dst_ip}:{dest_port}', False
            
            if stream_number not in streams: # Got a new flow number
                # Skip single resets packets
                if packet.tcp.flags_reset == '1':
                    continue
                
                streams[stream_number] = Vector(len(packet), src, dst, fwd, stream_number, flags)
            else: # New packet of existing flow
                vector = streams[stream_number]
                #  Divide large flow into small portions
                if find_packet_time(packet) - vector.packet_index > 2:
                    vector.finished = True
                    vector.packet_index = find_packet_time(packet)
                    flow_finished(vector)
                # Aggregate the packet's feature to the existing flow
                vector.add_packet(len(packet), packet.tcp.time_delta, src, flags)

            vector = streams[stream_number]
            update_flow_state(vector, packet)
            # End a flow in FYN or RST flag is opened
            if vector.state == 'CLOSED':
                # Add the whole flow - after he terminated to tri_graph
                vector.packet_index = find_packet_time(packet)
                flow_finished(vector)
                streams.pop(stream_number)
            
        if algo == 'network':
            continue
        
        # Compute the embeddings and the ANN every 100 flows
        if tri_graph.count_flows - prev_count_flows >= 100:
            embeddings = tri_graph.create_embeddings()
            if algo == 'ann':
                anomalies = ann_algorithm(tri_graph.graph, embeddings.detach().numpy())
            elif algo == 'clustering':
                cluster_embeddings = embeddings.detach().numpy()
                clusters = clustering_algorithm(cluster_embeddings)
                check_all_anomalies(tri_graph.graph, cluster_embeddings, clusters)
            if plot:
                plot_embeddings(embeddings, tri_graph.graph)
            prev_count_flows = tri_graph.count_flows
