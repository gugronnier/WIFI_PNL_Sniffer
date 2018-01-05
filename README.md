# WIFI_PNL_Sniffer
A python script to sniff for wifi pnl becons, this will show what SSID's the devices are looking for.

WIFI devices will send beacons out looking for SSID's that they have previously connected to, Prefered Netowrk List (PNL)
This sniffer will sniff and capture these becons and visualize them for you.

Requirements
pip install requirements.txt

Usage:
First run:
airmon-ng check kill
And put your wifi network card in monitor mode
airmon-ng start wlan0 

.\pnlscanner.py -i wlan0mon -w capture.cap

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to be used for capture
  -w WRITE, --write WRITE
                        Write to capture pcap file

Example: ./pnlsniffer.py -i wlan0mon -w output.cap

