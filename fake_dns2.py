#!/usr/bin/env python

from scapy.all import *
from optparse import OptionParser
import socket
import struct



## Change an into to an IP
# this code copied from http://snipplr.com/view/14807/convert-ip-to-int-and-int-to-ip/
def intToIP( intip ):
	octet = ''
	for exp in [3,2,1,0]:
		octet = octet + str(intip / ( 256 ** exp )) + "."
		intip = intip % ( 256 ** exp )
	return(octet.rstrip('.'))
	
class MagicDNS:
	
	def __init__(self, iface):
		
		self.iface = iface
		# Create a dictionary (python speak for associative array) to remember name/IP associations
		self.dnsrecs = {}
		
		
	def magic_dns(self, pkt):
		# only look for queries
		if DNS in pkt and pkt[DNS].qr == 0:
			# Create and remember a random IP - the range is just to give a 'realistic' ish feel, so you don't get something like 0.0.4.5
			ip = random.randrange(16000000,3500000000)
			ip = intToIP(ip)
			self.dnsrecs.setdefault(pkt[DNSQR].qname, ip) # The 'setdefault' method will set the value only if it hasn't already been set
		
			# create a response packet
			# This is all done with scapy functions/objects
			print "DNS: Resolved %s to %s" % (pkt[DNSQR].qname, self.dnsrecs[pkt[DNSQR].qname])
			sendp(    Ether(src=pkt[Ether].dst, dst = pkt[Ether].src) /
				IP(src=pkt[IP].dst, dst = pkt[IP].src) /             # IP header
				UDP(sport = 53, dport = pkt[UDP].sport) /         # UDP header
				DNS(id=pkt[DNS].id, qr = 1, opcode=0, aa=1, rcode=0, qdcount=1,ancount=1,
					qd=DNSQR(qname=pkt[DNSQR].qname, qtype=1, qclass=1),
					an=DNSRR(rrname=pkt[DNSQR].qname, type=1, rclass = 1, ttl=120,rdata=self.dnsrecs[pkt[DNSQR].qname]), ns=0, ar=0),
					iface = self.iface)


def main():
	
	clparser = OptionParser()

	clparser.add_option("-i", "--interface", help="Interface to listen and send pkts on", action="store", type="string", dest="iface")
	

	(options, args) = clparser.parse_args()
	
	# instantiate new class
	
	new_magic = MagicDNS(options.iface)
	
		
	# set up a sniffer with a callback function to 'magic_dns'. Filter for only stuff going to port 53
	sniff(prn=new_magic.magic_dns, filter="udp dst port 53", store=0, iface=options.iface)
		

if __name__ == "__main__":
	main()

