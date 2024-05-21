import numpy as np

# For clustering
import hdbscan

# For anomalies
from sklearn.metrics import pairwise_distances_argmin_min


# Function to perform clustering algorithm
def clustering_algorithm(graph, embeddings): 
    
    # Initialize HDBSCAN
    clusterer = hdbscan.HDBSCAN(min_cluster_size=5, gen_min_span_tree=True, metric='euclidean')
    
    # Perform clustering
    cluster_labels = clusterer.fit_predict(embeddings)
    
    return cluster_labels

#Function to calculte the amount of every cluster
def count_vectors_in_clusters(labels):
    unique_labels, counts = np.unique(labels, return_counts=True)
    cluster_counts = dict(zip(unique_labels, counts))
    return cluster_counts

# Function to measure distance of a cluster
def find_centroids(vectors, labels):
    # Calculate centroids for each cluster
    centroids = []
    for cluster in np.unique(labels):
        cluster_points = vectors[labels == cluster]
        centroid = np.mean(cluster_points, axis=0)
        centroids.append(centroid)
    
    # Convert centroids to a NumPy array
    return np.array(centroids)

def calculate_centroid_distances(centroids):
    distances = []
    for i in range(len(centroids)):
        list_without_current = np.delete(centroids, i, axis=0)
        current_distance = pairwise_distances_argmin_min(centroids, list_without_current, metric='euclidean')[1]
        distances.append(current_distance[i])
    return distances

# Function to measure density of a cluster
def calculate_density(vectors, labels):
    densities = []
    for cluster in np.unique(labels):
        cluster_points = vectors[labels == cluster]
        centroid = np.mean(cluster_points, axis=0)
        distances = pairwise_distances_argmin_min(cluster_points, [centroid])[1]
        current_density = np.mean(distances)
        densities.append(current_density)
    return densities

def check_anomalies(elements, threshold=1.5):
    avg_distance = np.mean(elements)
    std_distance = np.std(elements)
    
    unusual_distances = [i for i in range(len(elements)) 
                        if (elements[i] > avg_distance + threshold * std_distance) 
                        or  (elements[i] < avg_distance - threshold * std_distance)]
    
    return unusual_distances

def check_all_anomalies(embeddings, clusters):
    # Count the number of vectors in each cluster
    cluster_counts = count_vectors_in_clusters(clusters)
    
    # Check for anomaly clusters count
    unusual_clusters = check_anomalies(list(cluster_counts.values()))
    if unusual_clusters:
        print("Number of vectors in each cluster:", cluster_counts)
        print("Unusual clusters (amount):", unusual_clusters)
        print()
        
    
    # Calculate densities in each cluster
    cluster_densities = calculate_density(embeddings, clusters)
    
    # Check for anomaly clusters
    unusual_clusters = check_anomalies(cluster_densities)
    if unusual_clusters:
        print("Densities in each cluster:", cluster_densities)
        print("Unusual clusters (density):", unusual_clusters)
        print()
        
    # Calculate distances between centroids
    centroids = find_centroids(embeddings, clusters)
    centroid_distances = calculate_centroid_distances(centroids)
    
    # Check for anomaly distances
    unusual_distances = check_anomalies(centroid_distances)
    if unusual_distances:
        print("Distances between centroids:", centroid_distances)
        print("Unusual distances:", unusual_distances)
        print()
        
    print()
    print()
