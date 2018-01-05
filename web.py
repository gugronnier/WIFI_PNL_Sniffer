#!/usr/bin/env python
import argparse
import pydot
import sys, getopt, os
import SimpleHTTPServer
import SocketServer


def website():
	PORT = 8080
	Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
	httpd = SocketServer.TCPServer(("", PORT), Handler)
	print "serving at port", PORT
	httpd.serve_forever()
	#pass
	#test()


def main():
	parser = argparse.ArgumentParser(description='PNL sniffer.')
	parser.add_argument('-i','--interface', help='Interface used to sniff traffic',required=False)
	parser.add_argument('-w','--write', help='Saves captured traffic to a capture file',required=False)
	parser.add_argument('-p','--pnl', help='Fix pnl file',required=False)
	parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
#	parser.add_argument('-e', '--example', help='shows example')
	args = parser.parse_args()
	web()

def test():
	print("test")

if __name__ == '__main__':
    main()
