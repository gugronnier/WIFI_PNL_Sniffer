# WIFI_PNL_Sniffer
A python script to sniff for wifi pnl becons, this will show what SSID's the devices are looking for.

WIFI devices will send beacons out looking for SSID's that they have previously connected to, Prefered Netowrk List (PNL)
This sniffer will sniff and capture these becons and visualize them for you.

Requirements
import argparse
import pydot
import sys, getopt, os
import subprocess
import pdb
import threading
import time
from scapy.all import *

Installation
sudo apt-get install python-scapy

#to install pip
wget https://bootstrap.pypa.io/get-pip.py
sudo python get-pip.py

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

