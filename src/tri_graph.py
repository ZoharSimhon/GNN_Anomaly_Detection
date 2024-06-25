from queue import Queue
import networkx as nx
from networkx import NetworkXError
from vector import Vector

colors = ["lightskyblue", "lightcoral","lightgreen", "limegreen", "crimson", "darkgray",
          "deeppink", "olivedrab", "blueviolet", "firebrick", "orange", "tomato", "maroon", "orchid", 
          "peru","yellow"]

# Define a class to represent a tri-graph structure for network traffic analysis
class TriGraph():
    def __init__(self, sliding_window_size = 1000) -> None:
        self.ip_to_id = {}
        self.graph = nx.Graph()
        self.count_flows = 1
        self.q = Queue(maxsize=sliding_window_size)
        self.ip_to_color = {}
    
    from graph_embedding import create_embeddings
    from visualization import visualize_directed_graph
    
    # Generate id number for ip:port
    def get_id(self, key):
        if key not in self.ip_to_id:
            self.ip_to_id[key] = f'{len(self.ip_to_id)}ip'
        return self.ip_to_id[key]

    # Generate color number for ip
    def get_color(self, ip):
        if ip not in self.ip_to_color:
            self.ip_to_color[ip] = colors[len(self.ip_to_color)%len(colors)]
        return self.ip_to_color[ip]

    def add_nodes_edges(self, vector: Vector):
        # define colors
        src_ip, dst_ip = vector.src.split(":")[0], vector.dst.split(":")[0]
        src_color, dst_color = self.get_color(src_ip), self.get_color(dst_ip)
        
        #  add nodes
        src_id, dst_id = self.get_id(vector.src), self.get_id(vector.dst)
        
        if not self.graph.has_node(src_ip):
            self.graph.add_node(src_ip, side = 'Client-IP', amount = 0, length = 0, time_delta = 0.0, 
                                min_packet_length = 0, max_packet_length = 0, mean_packet_length = 0,
                                FIN_count = 0,  SYN_count = 0,  RST_count = 0,  PSH_count = 0,  ACK_count = 0,  
                                URG_count = 0, ip = vector.src, flows = 1, color = src_color)
        
                
        if not self.graph.has_node(src_id):
            self.graph.add_node(src_id, side = 'Client', amount = 0, length = 0, time_delta = 0.0, 
                                min_packet_length = 0, max_packet_length = 0, mean_packet_length = 0,
                                FIN_count = 0,  SYN_count = 0,  RST_count = 0,  PSH_count = 0,  ACK_count = 0,  
                                URG_count = 0, ip = vector.src, flows = 0, color = src_color)
                
        if not self.graph.has_node(dst_id):
            self.graph.add_node(dst_id, side = 'Server', amount = 0, length = 0, time_delta = 0.0, 
                                min_packet_length = 0, max_packet_length = 0, mean_packet_length = 0,
                                FIN_count = 0,  SYN_count = 0,  RST_count = 0,  PSH_count = 0,  ACK_count = 0,  
                                URG_count = 0, ip = vector.dst, sip = vector.src, flows = 0, color = dst_color)
        
        self.update_features(src_ip, vector, 'fwd')
        self.update_features(src_id, vector, 'fwd')
        self.update_features(dst_id, vector, 'bwd')
        self.graph.nodes[src_ip]["flows"] -= 1
        
        # flow_node = vector.stream_number
        flow_node = f'{vector.stream_number}_{self.count_flows}f'
        if not self.graph.has_node(flow_node):
            self.graph.add_node(flow_node, side = 'Flow', amount = 0,  length = 0, time_delta = 0, 
                                stream_number = vector.stream_number, packet_index = vector.packet_index, 
                                min_packet_length = 0, max_packet_length = 0, sip = vector.src,
                                FIN_count = 0,  SYN_count = 0,  RST_count = 0,  PSH_count = 0,  ACK_count = 0,  
                                URG_count = 0, dip = vector.dst,  flows = 1, color = "violet")
            # update count_flows
            self.count_flows += 1
            
        self.update_features(flow_node, vector, 'flow')
                    
        # add edges
        if not self.graph.has_edge(src_ip, src_id):
            self.graph.add_edge(src_ip, src_id)
        if not self.graph.has_edge(src_id, flow_node):
            self.graph.add_edge(src_id, flow_node)
        if not self.graph.has_edge(flow_node, dst_id):
            self.graph.add_edge(flow_node, dst_id)
        
        
        # update q (FIFO style)
        if self.q.full():
            index = self.q.get()
            try:
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
            except NetworkXError as e:
                print(e)

        self.q.put(flow_node)
            

    def update_features(self, id, vector, direction):
        # Update features of a node in the graph
        node = self.graph.nodes[id]
        if direction == 'flow':
            node['amount'] += vector.fwd_packets_amount + vector.bwd_packets_amount
            node['length'] += vector.fwd_packets_length + vector.bwd_packets_length
            node['min_packet_length'] = min(vector.min_bwd_packet, vector.min_fwd_packet)
            node['max_packet_length'] = max(vector.max_bwd_packet, vector.max_fwd_packet)
            
        else:   
            node["flows"] += 1
            node['amount'] += getattr(vector, f'{direction}_packets_amount')
            node['length'] += getattr(vector, f'{direction}_packets_length')
            node['min_packet_length'] += getattr(vector, f'min_{direction}_packet')
            node['max_packet_length'] += getattr(vector, f'max_{direction}_packet')
            
        if  node['amount'] != 0:     
            node['mean_packet_length'] = node['length']/node['amount']
        node["time_delta"] +=  vector.time_delta
        node["packet_index"] = vector.packet_index
        for flag in vector.flags:
            node[f'{flag}_count'] += vector.flags[flag]
        