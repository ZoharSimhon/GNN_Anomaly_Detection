from pyshark import FileCapture
from time import time
from datetime import datetime

from ann import ann_algorithm
from vector import Vector
from tri_graph import TriGraph
from visualization import plot_embeddings
from clustering import check_all_anomalies, clustering_algorithm
    
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
    cap = FileCapture(pcap_file)
    tri_graph = TriGraph(sliding_window_size)
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
            tri_graph.visualize_directed_graph()
            prev_time = time()
        
        # Compute the embeddings and the ANN every 100 flows
        if tri_graph.count_flows - prev_count_flows >= 100:
            embeddings = tri_graph.create_embeddings()
            if algo == 'ann':
                anomalies = ann_algorithm(tri_graph.graph,embeddings.detach().numpy())
            elif algo == 'clustering':
                cluster_embeddings = embeddings.detach().numpy()
                clusters = clustering_algorithm(tri_graph.graph,cluster_embeddings)
                check_all_anomalies(cluster_embeddings, clusters)
            if plot:
                plot_embeddings(embeddings, tri_graph.graph)
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
                # Skip single resets packets
                if packet.tcp.flags_reset == '1':
                    continue
                if int(src_port) > int(dest_port):
                    src, dst = f'{src_ip}:{src_port}', f'{dst_ip}:{dest_port}'
                else:
                    dst, src = f'{src_ip}:{src_port}', f'{dst_ip}:{dest_port}'
                streams[stream_number] = Vector(len(packet), src, dst, stream_number)
            else: # New packet of existing flow
                vector = streams[stream_number]
                #  Divide large flow into small portions
                if find_packet_time(packet) - vector.packet_index > 2:
                    # vector.finished = True
                    vector.packet_index = find_packet_time(packet)
                    tri_graph.add_nodes_edges(vector)
                # Aggregate the packet's feature to the existing flow
                vector.add_packet(len(packet), packet.tcp.time_delta, src)

            vector = streams[stream_number]
            update_flow_state(vector, packet)
            # End a flow in FYN or RST flag is opened
            if vector.state == 'CLOSED':
                # Add the whole flow - after he terminated to tri_graph
                vector.packet_index = find_packet_time(packet)
                tri_graph.add_nodes_edges(vector)
                streams.pop(stream_number)