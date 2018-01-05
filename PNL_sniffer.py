#!/usr/bin/env python
import argparse
import pydot
import sys, getopt, os
import subprocess
import pdb
import threading
import time

from scapy.all import *

__author__ = 'Mattias Grondahl'

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

ap_list = []
ap_list2 = []

def format():
	header = u"{0:<24}{1:>30}".format('SSID', 'MAC')
	print(header)
	print("-"*len(header))
	for SSID, MAC in ap_list2:
		print(u"{0:<24}{1:>30}".format(SSID, str(MAC)))

def banner(interface, write):
	print bcolors.OKGREEN +'''
		 _____  _   _ _         _____       _  __  __          
		 |  __ \| \ | | |      / ____|     (_)/ _|/ _|         
		 | |__) |  \| | |      | (___  _ __  _| |_| |_ ___ _ __ 
		 |  ___/| . ` | |       \___ \| '_ \| |  _|  _/ _ \ '__|
		 | |    | |\  | |____   ____) | | | | | | | ||  __/ |   
		 |_|    |_| \_|______| |_____/|_| |_|_|_| |_| \___|_|   
	                                                        
	'''

	print (bcolors.OKBLUE + "_____________________________________________________________________________________________________________ " + bcolors.ENDC)
	print (bcolors.OKBLUE + "|\n| Interface name:			 	 " + bcolors.FAIL + " %s " % interface + bcolors.ENDC)
	print (bcolors.OKBLUE + "| Save catpure to:	            	       	 " + bcolors.FAIL + " %s " % write + bcolors.ENDC)
	print (bcolors.OKBLUE + "| Graph saved to:        			 " + bcolors.FAIL + " pnl.png " + bcolors.ENDC)
	print (bcolors.OKBLUE + "|____________________________________________________________________________________________________________ " + bcolors.ENDC)
	print (bcolors.FAIL + "\nPress CTRL + C to Cancel\n\n" + bcolors.ENDC)

def capture(interface, write):

	print("starting capture")
	print(str(interface) + " " + str(write))
	#Creates pnl.dot file
	f = open("pnl.dot", 'wb')
	f.write('import pydot\ngraph = pydot.Dot(graph_type=\'graph\')\n' )
	f.close()

	try:
		print('Press "q" to quit')
		t = threading.Thread(target=capture)
		t.start()
		while t.isAlive():
			#print("working", next(loop), end='\r', flush=True)
			time.sleep(0.25)
			pkts = sniff(iface=interface, prn = PacketHandler)
			wrpcap(write,pkts)
			print('\nYou pressed "q"!, Stopping.')
	except KeyboardInterrupt:
		print("quit!")
		pass
	#PacketHandler(interface, write)
	print("will try to fix pnl file")
	pnl()

def PacketHandler(pkt):
		#print(str(interface) + str(write))
		#Defines Capture

		if pkt.haslayer(Dot11) :
			if pkt.type == 0 and pkt.subtype == 4 :
				if pkt.addr2 not in ap_list :
					ap_list.append(pkt.addr2)
					ap_list2.append([pkt.addr2, pkt.info])
					print "%s looking for SSID: %s " %(pkt.addr2, pkt.info)
					f = open('pnl.dot', 'a')
					f.write('edge = pydot.Edge("%s", "%s")\ngraph.add_edge(edge)\n' %(pkt.addr2, pkt.info))
					print("Sniffing for new SSID and PNL...")
				

#Append the in the end of the file
def pnl():
	print("ap list contains " + str(ap_list2))
	format()
	f = open("pnl.dot", 'a')
	f.write('graph.write_png(\'example1_graph.png\')\n')
	f.close()
	replacements = {':':'\:', '\"\"':'\"beacon\"'}
	with open('pnl.dot') as infile, open('pnl.fix', 'w') as outfile:
	    for line in infile:
	       	for src, target in replacements.iteritems():
	            line = line.replace(src, target)
	        outfile.write(line)
	execfile("pnl.fix")


def main():

	parser = argparse.ArgumentParser(description='PNL sniffer.')
	parser.add_argument('-i','--interface', help='Interface used to sniff traffic',required=False)
	parser.add_argument('-w','--write', help='Saves captured traffic to a capture file',required=False)
	parser.add_argument('-p','--pnl', help='Fix pnl file',required=False)
	parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
#	parser.add_argument('-e', '--example', help='shows example')
	args = parser.parse_args()
	
	if (args.pnl != None):
		pnl()

	#Print Help
	if (args.interface == None):
		parser.print_help()
		sys.exit(1)

	

	# Assign args to variables
	interface = args.interface
	write = args.write

	# Return all variable values
#	return interface, write
#	interface, write = get_args()

	banner(interface, write)
	capture(interface, write)

if __name__ == '__main__':
    main()
