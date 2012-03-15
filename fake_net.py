#!/usr/bin/env python

from scapy.all import *
from optparse import OptionParser
import fake_dns2
import fake_arp
import sys

class MagicNet():
	
	def __init__(self, iface):
		
		self.iface = iface
		
		# instantiate new classes
		self.arp = fake_arp.MagicARP(iface)
		self.dns = fake_dns2.MagicDNS(iface)
		

	def magic_net(self, pkt):
		
		if ARP in pkt:
			self.arp.magic_arp(pkt)
			
		elif DNS in pkt:
			self.dns.magic_dns(pkt)

def main():
	
	clparser = OptionParser()

	clparser.add_option("-i", "--interface", help="Required - interface to listen and send pkts on", action="store", type="string", dest="iface")
	
	(options, args) = clparser.parse_args()
	
	if not options.iface:
		parser.print_help()
		sys.exit(1)
	
	# new class
	magic = MagicNet(options.iface)	
		
	# set up a sniffer with a callback function to 'magic_dns'. Filter for only stuff going to port 53
	sniff(prn=magic.magic_net, filter="arp or udp dst port 53", store=0, iface=options.iface)
		

if __name__ == "__main__":
	main()

