#!/usr/bin/env python
import argparse
import pydot
import sys, getopt, os
import subprocess
import pdb
from scapy.all import *

#try:
#	from scapy.all import *
#except ImportError, error:
#	raise Exception("Your pnlsniffer installation is broken, could not import libraries: %s" %(error))

#Future features
# -A to include AP in graphs
# -C to include clients
# -t time to build graphs ex -t 30 a graph will be created every 30 sec
#args = parser.parse_args()
#if args.verbose:
#    print "verbosity turned on"

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''


parser = argparse.ArgumentParser(description='PNL sniffer.')
parser.add_argument('-i','--interface', help='Interface used to sniff traffic',required=True)
parser.add_argument('-w','--write', help='Saves captured traffic to a capture file',required=False)
#parser.add_argument('-v', action='append_const', dest='const_collection',	
#                    const='value-2-to-append',
#                    help='Add different values to list')
#parser.add_argument('--version', action='version', version='%(prog)s 1.0')
args = parser.parse_args()

#if not args.interface:
#  parser.print_usage()
#  sys.exit(2)

print '''
 _____  _   _ _         _____       _  __  __          
 |  __ \| \ | | |      / ____|     (_)/ _|/ _|         
 | |__) |  \| | |      | (___  _ __  _| |_| |_ ___ _ __ 
 |  ___/| . ` | |       \___ \| '_ \| |  _|  _/ _ \ '__|
 | |    | |\  | |____   ____) | | | | | | | ||  __/ |   
 |_|    |_| \_|______| |_____/|_| |_|_|_| |_| \___|_|   
                                                        
'''

print (bcolors.OKBLUE + "Running against: " + bcolors.WARNING + args.interface + bcolors.ENDC)
print (bcolors.OKBLUE + "Capturing to: " + bcolors.WARNING + args.write + bcolors.ENDC)
print (bcolors.OKBLUE + "Loggin to: " + bcolors.WARNING + "pnl.dot" + bcolors.ENDC)
print (bcolors.FAIL + "Press CTRL + C to Cancel" + bcolors.ENDC)

#Creates pnl.dot file
f = open("pnl.dot", 'wb')
f.write('import pydot\ngraph = pydot.Dot(graph_type=\'graph\')\n' )
f.close()

#Defines Capture
ap_list = []
def PacketHandler(pkt) :
		if pkt.haslayer(Dot11) :
			if pkt.type == 0 and pkt.subtype == 4 :
				if pkt.addr2 not in ap_list :
					ap_list.append(pkt.addr2)
					print "%s looking for SSID: %s " %(pkt.addr2, pkt.info)
					f = open('pnl.dot', 'a')
					f.write('edge = pydot.Edge("%s", "%s")\ngraph.add_edge(edge)\n' %(pkt.addr2, pkt.info))

pkts = sniff(iface=args.interface, prn = PacketHandler)
wrpcap(args.write,pkts)

#Append the inthe end of the file
f = open("pnl.dot", 'a')
f.write('graph.write_png(\'example1_graph.png\')\n')
f.close()

replacements = {':':'\:', '\"\"':'\"beacon\"'}
with open('/root/Wifi/pnl.dot') as infile, open('/root/Wifi/pnl.fix', 'w') as outfile:
    for line in infile:
       	for src, target in replacements.iteritems():
            line = line.replace(src, target)
        outfile.write(line)
execfile("pnl.fix")
