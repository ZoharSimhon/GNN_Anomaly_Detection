import numpy as np
from annoy import AnnoyIndex

from config import threshold

BASE_LINE_AMOUNT = 100

class ANN():
    def __init__(self) -> None:
        self.index = None
    
    def create_index(self, dim):
        # Create an Annoy index
        dimension = dim  # Number of features in the vectors
        self.index = AnnoyIndex(dimension, 'euclidean')
        self.vectors = []

        # Build the index
        self.index.build(10)  # 10 trees
        self.num_neighbors = 4  # Number of neighbors to find
        self.number_of_vectors = 0

        self.mean_distances = np.array([])

    # Add a new vector to the annoy index
    def add_vector(self, vector):
        flags = list(vector.flags.values())
        attribute_values = flags + list(vector.__dict__.values())[8:]
        vector_np = np.array(attribute_values)
        
        if self.index is None:
            self.create_index(len(vector_np))
        self.index.add_item(self.number_of_vectors, vector_np)
        self.vectors.append(vector_np)
        self.number_of_vectors += 1

        # Not calculating anomaly score for the first n vectors
        if self.number_of_vectors < BASE_LINE_AMOUNT:
            return 'base-line'

        # Calculate distances for the first n vectors
        if self.number_of_vectors == BASE_LINE_AMOUNT:
            for i in range (BASE_LINE_AMOUNT):
                distances = self.index.get_nns_by_item(i, self.num_neighbors, include_distances=True, search_k=-1)[1]
                distances = distances[1:]
                mean_distance = np.mean(distances)
                self.mean_distances = np.append(self.mean_distances, mean_distance)
            return 'base-line'
        
        # Calculate anomaly scores
        distances = self.index.get_nns_by_item(self.number_of_vectors-1, self.num_neighbors, include_distances=True, search_k=-1)[1]
        distances = distances[1:]
        mean_distance = np.mean(distances)
        all_means = np.mean(self.mean_distances)
        all_std = np.std(self.mean_distances)
        # self.mean_distances = np.append(self.mean_distances, mean_distance)
        # anomaly_score = 1- (min(mean_distance, all_means)/ max(mean_distance, all_means))

        # Thresholding
        if mean_distance > all_means + threshold * all_std:
            return 'anomaly', mean_distance
        else:
            self.mean_distances = np.append(self.mean_distances, mean_distance)
            return 'normal', mean_distance
