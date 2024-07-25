from flow_separation import run_algo
    
if __name__ == '__main__':

    pcap_file_path = '..\\data\\Wednesday-workingHours.pcap'
    # pcap_file_path = '..\\data\\04022024_1330_1634.pcap'
    run_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=50000, algo='network', plot=False)
    # run_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=50000, algo='clustering', plot=False)

