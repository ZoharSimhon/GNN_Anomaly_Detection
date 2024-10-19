@echo off

REM REM xss attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-XSS.pcap_ISCX.csv 1000 > ..\output\clustering_results\xss_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-XSS.pcap_ISCX.csv 2000 > ..\output\clustering_results\xss_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-XSS.pcap_ISCX.csv 4000 > ..\output\clustering_results\xss_4000_end_arg.txt

REM ftp attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/Tuesday-ftp.pcap_ISCX.csv 1000 > ..\output\clustering_results\ftp_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Tuesday-ftp.pcap_ISCX.csv 2000 > ..\output\clustering_results\ftp_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Tuesday-ftp.pcap_ISCX.csv 4000 > ..\output\clustering_results\ftp_4000_end_arg.txt

REM BruteForce attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-BruteForce.pcap_ISCX.csv 1000 > ..\output\clustering_results\BruteForce_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-BruteForce.pcap_ISCX.csv 2000 > ..\output\clustering_results\BruteForce_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-BruteForce.pcap_ISCX.csv 4000 > ..\output\clustering_results\BruteForce_4000_end_arg.txt

REM SQL_injection attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-SQL_injection.pcap_ISCX.csv 1000 > ..\output\clustering_results\SQL_injection_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-SQL_injection.pcap_ISCX.csv 2000 > ..\output\clustering_results\SQL_injection_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-SQL_injection.pcap_ISCX.csv 4000 > ..\output\clustering_results\SQL_injection_4000_end_arg.txt

REM dos_slowloris attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/Wednesday-dos-slowloris.pcap_ISCX.csv 1000 > ..\output\clustering_results\dos_slowloris_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Wednesday-dos-slowloris.pcap_ISCX.csv 2000 > ..\output\clustering_results\dos_slowloris_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Wednesday-dos-slowloris.pcap_ISCX.csv 4000 > ..\output\clustering_results\dos_slowloris_4000_end_arg.txt

REM dos_goldeneye attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/Wednesday-dos-goldeneye.pcap_ISCX.csv 1000 > ..\output\clustering_results\dos_goldeneye_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Wednesday-dos-goldeneye.pcap_ISCX.csv 2000 > ..\output\clustering_results\dos_goldeneye_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Wednesday-dos-goldeneye.pcap_ISCX.csv 4000 > ..\output\clustering_results\dos_goldeneye_4000_end_arg.txt

REM Infilteration attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-Infilteration.pcap_ISCX.csv 1000 > ..\output\clustering_results\Infilteration_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-Infilteration.pcap_ISCX.csv 2000 > ..\output\clustering_results\Infilteration_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Thursday-Infilteration.pcap_ISCX.csv 4000 > ..\output\clustering_results\Infilteration_4000_end_arg.txt

REM hulk attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/hulk.csv 1000 > ..\output\clustering_results\hulk_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/hulk.csv 2000 > ..\output\clustering_results\hulk_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/hulk.csv 4000 > ..\output\clustering_results\hulk_4000_end_arg.txt

REM bot attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/Friday-BOT-Morning.pcap_ISCX.csv 1000 > ..\output\clustering_results\bot_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Friday-BOT-Morning.pcap_ISCX.csv 2000 > ..\output\clustering_results\bot_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Friday-BOT-Morning.pcap_ISCX.csv 4000 > ..\output\clustering_results\bot_4000_end_arg.txt

REM ssh attack
python .\csv_reading.py ../data/cic-ids-2017-seperated/Tuesday-ssh.pcap_ISCX.csv 1000 > ..\output\clustering_results\ssh_1000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Tuesday-ssh.pcap_ISCX.csv 2000 > ..\output\clustering_results\ssh_2000_end_arg.txt
python .\csv_reading.py ../data/cic-ids-2017-seperated/Tuesday-ssh.pcap_ISCX.csv 4000 > ..\output\clustering_results\ssh_4000_end_arg.txt

echo All commands have been executed.
pause