from pyshark import FileCapture
import numpy as np
import matplotlib.pyplot as plt
from annoy import AnnoyIndex

BASE_LINE_AMOUNT = 100

class ANN():
    def __init__(self) -> None:
        # Create an Annoy index
        dimension = 3  # Number of features in the vectors
        self.index = AnnoyIndex(dimension, 'euclidean')

        # Build the index
        self.index.build(10)  # 10 trees
        self.num_neighbors = 4  # Number of neighbors to find
        self.number_of_vectors = 0

        self.mean_distances = np.array([])

    # Add a new vector to the annoy index
    def add_vector(self, vector):
        vector_np = np.array([vector.length if vector.length != 4806 else 4807, vector.time_delta, vector.amount])
        self.index.add_item(self.number_of_vectors, vector_np)
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
        self.mean_distances = np.append(self.mean_distances, mean_distance)
        anomaly_score = 1- (min(mean_distance, all_means)/ max(mean_distance, all_means))


        # Thresholding
        threshold = 0.95
        if anomaly_score > threshold and mean_distance > all_means:
            print(distances)
            print(mean_distance)
            print(all_means)
            return 'anomaly', anomaly_score
        else:
            self.mean_distances = np.append(self.mean_distances, mean_distance)
            return 'normal', anomaly_score

# For represent the flow as vector
class Vector():
    # Create new vector with one packet 
    def __init__(self, length, src_ip, dst_ip, stream_number) -> None:
        self.length = length
        self.amount = 1
        self.time_delta = 0.0
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.finished = False
        self.stream_number = stream_number

    # Aggregate the features of the new packet 
    def add_packet(self, length, time_delta):
        if self.finished:
            self.reset()
        self.amount += 1
        self.length += length
        new_time_delta = self.time_delta + float(time_delta)
        self.time_delta = round(new_time_delta, 6)
    
    # Initialize the features on flow termination
    def reset(self):
        self.length = 0
        self.amount = 0
        self.time_delta = 0.0
        self.finished = False
        
    def __str__(self) -> str:
        return f'length: {self.length}, amount: {self.amount}, time_delta: {self.time_delta}, src_ip: {self.src_ip}, dst_ip: {self.dst_ip}'
    def __len__(self) -> int:
        return self.amount
    

# Show the flows in 3D plot
def create_plot(vectors):
    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')

    for vector in vectors:
        # Vector's position is represented by its length, time_delta, and amount
        position = np.array([vector.length, vector.time_delta, vector.amount])

        # Plot the vector as a point at the position
        ax.scatter(position[0], position[1], position[2], color='b')

    ax.set_xlabel('Length')
    ax.set_ylabel('Time Delta')
    ax.set_zlabel('Amount')    
    plt.ion()
    plt.show()
    plt.pause(0.9)


def run_algo(pcap_file, sliding_window_size, num_of_rows=500):
    cap = FileCapture(pcap_file)
    streams = []
    ann = ANN()
    for i, packet in enumerate(cap):
        if i == num_of_rows:
            return

        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            # Ignore retransmitted packets 
            if 'analysis_retransmission' in dir(packet.tcp):
                continue

            src_ip, dst_ip = packet.ip.src, packet.ip.dst

            stream_number = int(packet.tcp.stream)
            
            # First packet of a new flow 
            if len(streams) <= stream_number:
                streams.append(Vector(len(packet), src_ip, dst_ip, stream_number))
            
            # New packet of existing flow
            else:
                vector = streams[stream_number]
               
                # Teminate the flow on long time delta
                if vector.time_delta > 0.1:
                    vector.finished = True
                    
                    # Print the flow if found anomaly
                    if ann.add_vector(vector)[0] == 'anomaly':
                        print(f'anomaly on index {i}, stream: {stream_number}, vector: ',vector)
                
                # Aggregate the packet features to the existing flow 
                vector.add_packet(len(packet), packet.tcp.time_delta)

            if packet.tcp.flags_fin == '1' or packet.tcp.flags_reset == '1':
                vector = streams[stream_number]

                # If the flow is only fin, ignore it
                if vector.amount == 1:
                    vector.reset()
                    continue
                
                # Print the flow if found anomaly
                if ann.add_vector(vector)[0] == 'anomaly':
                    print(f'anomaly on index {i}, stream: {stream_number}, vector: ',vector)
                

                vector.finished = True
                




if __name__ == '__main__':

    pcap_file_path = '..\\data\\04022024_1330_1634.pcap'
    run_algo(pcap_file_path, 0, 50000)

