from pyshark import FileCapture
from time import time
from datetime import datetime

from ann import ann_algorithm
from vector import Vector
from tri_graph import TriGraph
from visualization import plot_embeddings
from clustering import check_all_anomalies, clustering_algorithm

def find_packet_time(packet):
    ts = int(float(packet.frame_info.time_epoch))
    return ts
    # return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

def run_algo(pcap_file, sliding_window_size, num_of_rows, algo='ann', plot=True):
    cap = FileCapture(pcap_file)
    tri_graph = TriGraph(sliding_window_size)
    prev_time = time()
    prev_count_flows = 0

    streams = {}
    
    for i, packet in enumerate(cap):
        if i == num_of_rows:
            return
        
        # Plot the graph every 2 seconds 
        if 2 <= time() - prev_time and plot:
            tri_graph.visualize_directed_graph()
            prev_time = time()
        
        # Compute the embeddings and the ANN every 10 flows
        if tri_graph.count_flows - prev_count_flows >= 10:
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
                # src, dst = f'{src_ip}:{src_port}', f'{dst_ip}:{dest_port}'
                if int(src_port) < int(dest_port):
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
                vector.add_packet(len(packet), packet.tcp.time_delta)

            vector = streams[stream_number]
            # End a flow in FYN or RST flag is opened
            if packet.tcp.flags_fin == '1' or packet.tcp.flags_reset == '1':
                # if the stream is only fin, ignore it
                if vector.amount == 1:
                    vector.reset()
                    continue
                
                # Add the whole flow - after he terminated to tri_graph
                vector.packet_index = find_packet_time(packet)
                tri_graph.add_nodes_edges(vector)
                streams.pop(stream_number)
