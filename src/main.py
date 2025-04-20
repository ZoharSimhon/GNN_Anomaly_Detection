import sys

from flow_separation import separate_packets_pcap
from flow_separation_csv import separate_packets_csv
from csv_reading import process_flows
# from config import dataset_type
# from config import feature_to_name

dataset_type = 'packets_csv'

feature_to_name = "feature_to_name_CIC_2017"

if __name__ == '__main__':

    # Check for command-line argument input_file_path
    if len(sys.argv) < 2:
        print('usage: main.py input_file_path num_of_flows')
        exit(1)
    input_file_path = sys.argv[1]

    # Check for command-line argument num_of_flows
    if len(sys.argv) < 3 or not sys.argv[2].isdecimal():
        num_of_flows = 2000
    else:
        num_of_flows = int(sys.argv[2])

    victom_ip = sys.argv[3]
    attacker_ip = sys.argv[4]

    if dataset_type == 'packets_csv':
        separate_packets_csv(input_file_path, num_of_rows=-1, algo='combined', plot=False, num_of_flows=num_of_flows, victom_ip=victom_ip, attacker_ip=attacker_ip, dataset_type=dataset_type)
    elif dataset_type == 'packets_pcap':
        separate_packets_pcap(input_file_path, num_of_rows=-1, algo='clustering', plot=False, num_of_flows=num_of_flows)
    else:
        process_flows(feature_to_name, input_file_path, num_of_flows, num_of_rows=-1, algo='clustering', plot=False)
