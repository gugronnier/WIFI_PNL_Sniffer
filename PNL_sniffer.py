#!/usr/bin/env python
from scapy.all import *
import argparse
import pydot

parser = argparse.ArgumentParser(description='PNL sniffer.')
parser.add_argument('-i','--interface', help='Interface used to sniff traffic',required=True)
parser.add_argument('-w','--write', help='Saves captured traffic to a capture file',required=True)
args = parser.parse_args()
print ("\nInterface:     %s" % args.interface )
print ("Pcap:            %s" % args.write )
print "Log:              wifi.log \n\nPress ctrl + c to cancel at anytime \n\nListening for wifi beacons from clients..."

#Creates pnl.dot file
f = open("pnl.dot", 'wb')
f.write('import pydot\ngraph = pydot.Dot(graph_type=\'graph\')\n' )
f.close()

#sniffer
ap_list = []
def PacketHandler(pkt) :
                if pkt.haslayer(Dot11) :
                        if pkt.type == 0 and pkt.subtype == 4 :
                                if pkt.addr2 not in ap_list :
                                        ap_list.append(pkt.addr2)
                                        print "Device MAC %s is looking AP with SSID: %s " %(pkt.addr2, pkt.info)
                                        f = open('pnl.dot', 'a')
                                        f.write('edge = pydot.Edge("%s", "%s")\ngraph.add_edge(edge)\n' %(pkt.addr2, pkt.info))


pkts = sniff(iface=args.interface, prn = PacketHandler)
wrpcap(args.write,pkts)

#Append the inthe end of the file
f = open("pnl.dot", 'a')
f.write('graph.write_png(\'example1_graph.png\')\n')
f.close()


#Replace
replacements = {':':'\:', '\"\"':'\"beacon\"'}

with open('pnl.dot') as infile, open('/root/Wifi/pnl.fix', 'w') as outfile:
    for line in infile:
        for src, target in replacements.iteritems():
            line = line.replace(src, target)
        outfile.write(line)

#draw graph
#graph.write_png('example1_graph.png')

#run file
execfile("pnl.fix")

