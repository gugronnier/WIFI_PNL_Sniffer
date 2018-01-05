
# WIFI_PNL_Sniffer
A python script to sniff for wifi pnl becons, this will show what SSID's the devices are looking for.

WIFI devices will send beacons out looking for SSID's that they have previously connected to, Prefered Netowrk List (PNL)
This sniffer will sniff and capture these becons and visualize them for you.

Installation
pip install https://pypi.python.org/packages/source/g/getch/getch-1.0-python2.tar.gz
pip install pydot

Or
sudo apt-get install python-pip

Usage:

First run:
airmon-ng check kill
And put your wifi network card in monitor mode
airmon-ng start wlan1

.\pnlscanner.py -i wlan1mon -w capture.cap

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to be used for capture
  -w WRITE, --write WRITE
                        Write to capture pcap file

Example: ./pnlsniffer.py -i wlan1mon -w output.cap
