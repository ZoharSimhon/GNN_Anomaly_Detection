from flow_separation import run_pcap_algo
from flow_separation_csv import run_csv_algo
from config import dataset

if __name__ == '__main__':

    pcap_file_path = '../data/2018csv/Infiltration-28-02.csv'
    if dataset == 'cic2018':
        run_csv_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=-1, algo='clustering', plot=False)
    else:
        run_pcap_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=-1, algo='clustering', plot=False)

