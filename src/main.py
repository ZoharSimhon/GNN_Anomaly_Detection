import sys
from flow_separation import run_pcap_algo
from flow_separation_csv import run_csv_algo
from config import dataset

if __name__ == '__main__':
    # If no pcap_file_path is provided, check for command-line argument
    if len(sys.argv) < 2:
        print('usage: main.py pcap_file_path num_of_flows')
        exit(1)
    pcap_file_path = sys.argv[1]

    if len(sys.argv) < 3 or not sys.argv[2].isdecimal():
        num_of_flows = 2000
    else:
        num_of_flows = int(sys.argv[2])

    victom_ip = sys.argv[3]
    attacker_ip = sys.argv[4]

    if dataset == 'cic2018':
        run_csv_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=-1, algo='clustering', plot=False, num_of_flows=num_of_flows, victom_ip=victom_ip, attacker_ip=attacker_ip)
    else:
        run_pcap_algo(pcap_file_path, sliding_window_size=1000, num_of_rows=-1, algo='clustering', plot=False, num_of_flows=num_of_flows)

