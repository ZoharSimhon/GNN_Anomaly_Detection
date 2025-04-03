from elasticsearch import Elasticsearch
from tri_graph import TriGraph
from network import ANN
from results import measure_results
from execute_pipeline import execute_pipeline

def process_flows_elastic(dic_feature_to_name, index_name, num_of_flows=None, num_of_rows=-1, algo='clustering', plot=False):
    if algo not in ['ann', 'clustering', 'combined']:
        print("No valid algorithm specified.")
        return

    tri_graph = TriGraph()

    # Connect to Elasticsearch
    es = Elasticsearch("http://localhost:9200")  # Adjust if needed

    # Start scrolling to fetch flows one by one
    response = es.search(index=index_name, scroll="2m", size=1000, body={"query": {"match_all": {}}})
    scroll_id = response["_scroll_id"]
    total_processed = 0

    pred = []
    label = []
    node_to_index = {}

    while total_processed != num_of_rows:  # Keep fetching until we reach the required number of rows
        hits = response["hits"]["hits"]
        if not hits:
            break  # Stop if no more data is available

        for i, hit in enumerate(hits):
            row = hit["_source"]  # Extract the actual flow data

            if total_processed % 10000 == 0:
                print(f'Processed {total_processed} flows')

            if total_processed == num_of_rows:
                break

            if row[dic_feature_to_name['Protocol']] != dic_feature_to_name['TCP']:
                continue  # Only process TCP flows

            tri_graph.add_flow_to_graph(row, pred, label, node_to_index, dic_feature_to_name)
            total_processed += 1

            if total_processed and total_processed % num_of_flows == 0:
                execute_pipeline(tri_graph, algo, plot, pred, node_to_index)

        # Fetch next batch of flows
        response = es.scroll(scroll_id=scroll_id, scroll="2m")
        scroll_id = response["_scroll_id"]

    # Final execution
    execute_pipeline(tri_graph, algo, plot, pred, node_to_index)
    measure_results(tri_graph.graph)
