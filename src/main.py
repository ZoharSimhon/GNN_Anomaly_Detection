from flow_separation import run_pcap_algo
from flow_separation_csv import run_csv_algo

INPUT_TYPE = 'csv'

if __name__ == '__main__':

    pcap_file_path = '../data/2018csv/output.csv'
    if INPUT_TYPE == 'csv':
        run_csv_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=-1, algo='clustering', plot=False)
    else:
        run_pcap_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=-1, algo='clustering', plot=False)

