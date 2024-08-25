
def check_anomalies(graph):
    for node in graph.nodes:
        graph.nodes[node]["pred"] = graph.nodes[node]["ann_pred"] or graph.nodes[node]["cluster_pred"]