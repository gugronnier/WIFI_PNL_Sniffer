# WIFI_PNL_Sniffer
A python script to sniff for wifi pnl becons, this will show what SSID's the devices are looking for.

WIFI devices will send beacons out looking for SSID's that they have previously connected to, Prefered Netowrk List (PNL)
This sniffer will sniff and capture these becons and visualize them for you.

Usage:

.\pnlscanner.py -i wlan1mon -w capture.cap

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to be used for capture
  -w WRITE, --write WRITE
                        Write to capture pcap file

