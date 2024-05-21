from flow_separation import run_algo
    
if __name__ == '__main__':

    # pcap_file_path = 'Thursday-WorkingHours.pcap'
    pcap_file_path = '081523-1308_1640.pcap'
    run_algo(pcap_file_path, 1000, 50000, 'ann')
    # run_algo(pcap_file_path, 1000, 50000, 'clustering')

