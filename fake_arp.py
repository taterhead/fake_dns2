#!/usr/bin/env python

from scapy.all import *
from optparse import OptionParser
import socket
import struct



	
class MagicARP:
	
	def __init__(self, iface):
		
		self.iface = iface
		self.macrecs = {}
		
		
	def magic_arp(self, pkt):
		# only look for queries
		if ARP in pkt and pkt[ARP].op == 1:
			
			# Get a random MAC address and remember it
			mac = get_random_mac()			
			self.macrecs.setdefault(pkt[ARP].pdst, mac) # The 'setdefault' method will set the value only if it hasn't already been set
			
			# create a response packet
			# This is all done with scapy functions/objects

			print "ARP: Resolved %s to %s" % (pkt[ARP].pdst, self.macrecs[pkt[ARP].pdst])
			sendp(    Ether(src=self.macrecs[pkt[ARP].pdst], dst = pkt[Ether].src, type = 2054) /
				ARP(hwtype = 1, ptype=0x800, hwlen=6, plen=4, op=2, 
					hwsrc=self.macrecs[pkt[ARP].pdst], 
					hwdst=pkt[Ether].src, 
					psrc=pkt[ARP].pdst,
					pdst=pkt[ARP].psrc), 
				iface = self.iface)
				
def get_random_mac():
	"""Generate a random MAC address"""
	
	# use the Dlink range
	mac = "00:05:5D"
	
	for i in range(0,3):
		mac += ":%s" % hex(random.randrange(0,256))[2:]
		
		
	return mac

def main():
	
	clparser = OptionParser()

	clparser.add_option("-i", "--interface", help="Interface to listen and send pkts on", action="store", type="string", dest="iface")
	

	(options, args) = clparser.parse_args()
	
	# instantiate new class
	
	new_magic = MagicARP(options.iface)
	
		
	# set up a sniffer with a callback function to 'magic_dns'. Filter for only stuff going to port 53
	sniff(prn=new_magic.magic_arp, filter="arp", store=0, iface=options.iface)
		

if __name__ == "__main__":
	main()

