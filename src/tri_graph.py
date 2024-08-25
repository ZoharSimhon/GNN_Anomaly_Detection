from queue import Queue
import networkx as nx
from networkx import NetworkXError

from vector import Vector

from config import attacker_ip, victom_ip

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
        self.gcn_model = None
    
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
        
        # check label
        src_label = src_ip in [attacker_ip, victom_ip]
        dst_label = dst_ip in [attacker_ip, victom_ip]
        
        #  add nodes
        src_id, dst_id = self.get_id(vector.src), self.get_id(vector.dst)
        
        if not self.graph.has_node(src_ip):
            self.graph.add_node(src_ip, side = 'Client-IP', amount = 0, length = 0, time_delta = 0.0, 
                                min_packet_length = 0, max_packet_length = 0, mean_packet_length = 0,
                                FIN_count = 0,  SYN_count = 0,  RST_count = 0,  PSH_count = 0,  ACK_count = 0,  
                                URG_count = 0, count_opened_sockets = 0, 
                                anomaly_score_history =  [], 
                                pred = False, label = src_label, cluster_pred = False, ann_pred = False,
                                ip = vector.src, flows = 1, color = src_color)
                
        if not self.graph.has_node(src_id):
            self.graph.add_node(src_id, side = 'Client', amount = 0, length = 0, time_delta = 0.0, 
                                min_packet_length = 0, max_packet_length = 0, mean_packet_length = 0,
                                FIN_count = 0,  SYN_count = 0,  RST_count = 0,  PSH_count = 0,  ACK_count = 0,  
                                URG_count = 0, count_opened_sockets = 0, 
                                anomaly_score_history =  [], 
                                pred = False, label = src_label, cluster_pred = False, ann_pred = False,
                                ip = vector.src, flows = 0, color = src_color)
                
            # update count_flows
            self.count_flows += 1

        if not self.graph.has_node(dst_id):
            self.graph.add_node(dst_id, side = 'Server', amount = 0, length = 0, time_delta = 0.0, 
                                min_packet_length = 0, max_packet_length = 0, mean_packet_length = 0,
                                FIN_count = 0,  SYN_count = 0,  RST_count = 0,  PSH_count = 0,  ACK_count = 0,  
                                URG_count = 0, count_opened_sockets = 0,
                                anomaly_score_history =  [],
                                pred = False, label = src_label, cluster_pred = False, ann_pred = False,
                                ip = vector.dst, sip = vector.src, flows = 0, color = dst_color)
        
        # add edges
        if not self.graph.has_edge(src_ip, src_id):
            self.graph.add_edge(src_ip, src_id)
        if not self.graph.has_edge(src_id, dst_id):
            self.graph.add_edge(src_id, dst_id)
        
        # update nodes features
        self.update_features(src_id, vector, 'fwd')
        self.update_features(src_ip, vector, 'fwd')
        self.update_features(dst_id, vector, 'bwd')
        
    def update_features(self, id, vector, direction):
        # Update features of a node in the graph
        node = self.graph.nodes[id]
        
        node["flows"] += 1
        node['amount'] += getattr(vector, f'{direction}_packets_amount')
        node['length'] += getattr(vector, f'{direction}_packets_length')
        node['min_packet_length'] += getattr(vector, f'min_{direction}_packet')
        node['max_packet_length'] += getattr(vector, f'max_{direction}_packet')
        
        if node['side'] == 'Client-IP':
            node['count_opened_sockets'] = 0
            node["flows"] = self.graph.degree(id)
            for neighbor in self.graph.neighbors(id):
                node['count_opened_sockets'] += self.graph.nodes[neighbor]["count_opened_sockets"]
        elif vector.state == 'CLOSED':
            node['count_opened_sockets'] = 0
        else:
            node['count_opened_sockets'] = 1
            
        if  node['amount'] != 0:     
            node['mean_packet_length'] = node['length']/node['amount']
        node["time_delta"] +=  vector.time_delta
        node["packet_index"] = vector.packet_index
        
        for flag in vector.flags:
            node[f'{flag}_count'] += vector.flags[flag]
        