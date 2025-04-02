from elasticsearch import Elasticsearch, helpers
import pandas as pd
import csv

# Elasticsearch connection (adjust credentials if necessary)
es = Elasticsearch("http://localhost:9200")  # Change to your ES host if needed
index_name = "network_traffic"  # Change to desired index name

# Read CSV file
csv_file = "../data/elastic/malware_attack_11_11.csv"  # Change to your actual CSV file path
df = pd.read_csv(csv_file)

# Convert DataFrame to a list of dictionaries
records = df.to_dict(orient="records")

# Prepare data for Elasticsearch bulk insert
def generate_data(records):
    for record in records:
        yield {
            "_index": index_name,
            "_source": record
        }

# Create the index (optional)
if not es.indices.exists(index=index_name):
    es.indices.create(index=index_name)

# Insert data in bulk
helpers.bulk(es, generate_data(records))

print("Data inserted into Elasticsearch successfully!")
