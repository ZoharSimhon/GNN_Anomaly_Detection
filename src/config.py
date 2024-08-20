features = ['amount', 'length', 'mean_packet_length', 
            'FIN_count', 'SYN_count', 'RST_count', 'PSH_count', 'ACK_count', 'URG_count',
            'count_opened_sockets', 
            # 'min_packet_length', 'max_packet_length',
            ]

anomaly_score_history_size  = 10
ann_threshold = 14
ann_history_threshold = 20
clustering_threshold = 5
network_threshold = 14

attacker_ip = ""
victom_ip = ""