# from elasticsearch import Elasticsearch

# # Connecting to Elasticsearch
# client = Elasticsearch(
#     "http://localhost:9200/",  # Elasticsearch endpoint
#     # api_key="api_key",
# )

# # Creating an index
# client.indices.create(index="my_index")

# # Indexing Documents
# client.index(
#     index="my_index",
#     id="my_document_id",
#     document={
#         "foo": "foo",
#         "bar": "bar",
#     }
# )

# # Getting Documents
# doc = client.get(index="my_index", id="my_document_id")
# print(doc)

# # Searching Documents
# foo = client.search(index="my_index", query={
#     "match": {
#         "foo": "foo"
#     }
# })
# print(foo)

# # Updating Documents
# client.update(index="my_index", id="my_document_id", doc={
#     "foo": "bar",
#     "new_field": "new value",
# })

# # Deleting Documents
# client.indices.delete(index="my_index")

# # Deleting an Index
# client.delete(index="my_index", id="my_document_id")

from elasticsearch import Elasticsearch
from tri_graph import TriGraph
from network import ANN
from results import measure_results
from execute_pipeline import execute_pipeline

def process_flows(dic_feature_to_name, es_host, es_index, query={}, num_of_flows=None, num_of_rows=-1, algo='clustering', plot=False):
    """
    Fetches flow data from Elasticsearch and processes it.
    
    :param dic_feature_to_name: Dictionary mapping feature names.
    :param es_host: Elasticsearch host (e.g., 'http://localhost:9200').
    :param es_index: Index name in Elasticsearch.
    :param query: Query dictionary for Elasticsearch (default: empty to fetch all).
    :param num_of_flows: Number of flows to process per batch.
    :param num_of_rows: Max number of rows to process (-1 for no limit).
    :param algo: Algorithm to use ('ann', 'clustering', 'combined').
    :param plot: Whether to generate plots.
    """

    # Connect to Elasticsearch
    es = Elasticsearch(es_host)
    
    if algo not in ['ann', 'clustering', 'combined']:
        print("No valid algorithm specified.")
        return
    
    tri_graph = TriGraph()
    
    # Elasticsearch Scroll API to handle large datasets
    scroll_time = "2m"  # Keep search context open for 2 minutes
    batch_size = 10000   # Number of results per request
    
    response = es.search(
        index=es_index,
        body={"query": query, "size": batch_size, "scroll": scroll_time}
    )

    scroll_id = response['_scroll_id']
    hits = response['hits']['hits']
    
    pred = []
    label = []
    node_to_index = {}

    processed_count = 0

    while hits:
        for row in hits:
            row_data = row['_source']  # Extract actual document data
            print(row_data)

            # if processed_count % 10000 == 0:
            #     print(f'Processed {processed_count} flows')

            # if num_of_rows != -1 and processed_count >= num_of_rows:
            #     break

            # if row_data[dic_feature_to_name['Protocol']] != dic_feature_to_name['TCP']:
            #     continue

            # tri_graph.add_flow_to_graph(row_data, pred, label, node_to_index, dic_feature_to_name)

            # if processed_count and num_of_flows and processed_count % num_of_flows == 0:
            #     execute_pipeline(tri_graph, algo, plot, pred, node_to_index)

            # processed_count += 1

        # Fetch next batch using scroll API
        response = es.scroll(scroll_id=scroll_id, scroll=scroll_time)
        hits = response['hits']['hits']

    # execute_pipeline(tri_graph, algo, plot, pred, node_to_index)
    # measure_results(tri_graph.graph)

    # Clear Elasticsearch scroll context
    es.clear_scroll(scroll_id=scroll_id)


dic_feature_to_name = {
    "Protocol": "protocol",
    "TCP": "TCP"
}

process_flows(
    dic_feature_to_name=dic_feature_to_name,
    es_host="http://localhost:9200",
    es_index="network_traffic",
    query={"match_all": {}},  # Fetch all records
    num_of_flows=5000,
    num_of_rows=50000,
    algo="clustering",
    plot=True
)
