
def check_anomalies(graph):
    for node in graph.nodes:
        graph.nodes[node]["pred"] = graph.nodes[node]["cluster_pred"] or ( graph.nodes[node]["ann_pred"] and graph.nodes[node]["cluster"] == -1)