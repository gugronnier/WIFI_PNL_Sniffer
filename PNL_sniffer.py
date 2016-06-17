#!/usr/bin/env python
from scapy.all import *
import argparse

parser = argparse.ArgumentParser(description='PNL sniffer.')
parser.add_argument('-i','--interface', help='Interface to be used for capture',required=True)
parser.add_argument('-w','--write', help='Write to capture file',required=True)
args = parser.parse_args()
print ("\nInterface:     %s" % args.interface )
print ("Pcap:            %s" % args.write )
print "Log:              wifi.log \n\nPress ctrl + c to cancel at anytime \n\nListening for wifi beacons from clients..."

ap_list = []
def PacketHandler(pkt) :
                if pkt.haslayer(Dot11) :
                        if pkt.type == 0 and pkt.subtype == 4 :
                                if pkt.addr2 not in ap_list :
                                        ap_list.append(pkt.addr2)
                                        print "Device MAC %s is looking AP with SSID: %s " %(pkt.addr2, pkt.info)
                                        f = open('wifi.log', 'a')
                                        f.write('"%s" -> "%s" [label = "WIFI Beacon"] \n' %(pkt.addr2, pkt.info))
pkts = sniff(iface=args.interface, prn = PacketHandler)
wrpcap(args.write,pkts)
