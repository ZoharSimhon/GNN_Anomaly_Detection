# Define a class to represent a vector of network traffic data
class Vector():
    def __init__(self, length, src, dst, stream_number) -> None:
        self.length = length
        self.amount = 1
        self.time_delta = 0.0
        self.src = src
        self.dst = dst
        self.finished = False
        self.stream_number = stream_number
        self.packet_index = 0
        self.state = 'ESTABLISHED'

    # Aggregate the features on existing stream
    def add_packet(self, length, time_delta):
        if self.finished:
            self.reset()
        self.amount += 1
        self.length += length
        new_time_delta = self.time_delta + float(time_delta)
        self.time_delta = round(new_time_delta, 3)
    
    def reset(self):
        self.length = 0
        self.amount = 0
        self.time_delta = 0.0
        self.finished = False
        
    def __str__(self) -> str:
        return f'length: {self.length}, amount: {self.amount}, time_delta: {self.time_delta}, src: {self.src}, dst: {self.dst}, stream: {self.stream_number}'
    def __len__(self) -> int:
        return self.amount
