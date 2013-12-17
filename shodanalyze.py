#!/usr/bin/env python

from bs4 import BeautifulSoup
from scapy.all import *

#import os

# class SCAN:
#	def __init__():
#		pass
# 	def syn_scan():
#		pass
# 	def ack_scan():
#		pass	
# 	def full_scan():
#		pass
# 	def xmass_scan():
#		pass

# class IP_RES:
#
#	def __init__();
#		pass
#	def add_resolve():
#		pass
#	def ip_range():
#		pass
#	def ip_cidr():
#		pass


def SYN_SCAN(SYN_dst, SYN_sport, SYN_dport):
	
	ip = IP(dst = SYN_dst)
	tcp = TCP(sport = SYN_sport, dport = SYN_dport, flags = "S")	
	mypacket = ip/tcp
	ans, unans = sr(mypacket, retry=-2, timeout=1)
	print "[+] Answered: ", ans.summary()
#	for a_snd, a_rcv in ans:
#		print a_snd.show()
#		print a_rcv.show()
	print "[-] Unanswered: ", unans.summary() 

# main()
xml = open('shodan.xml','r').read()
bs = BeautifulSoup(xml, "xml")

for item in bs.find_all('host'):

	print "Pinging " + item['ip']
#	os.system("hping3 -S -p 80 -c 1 " + item['ip']) <= using os library for hping command invoke
	SYN_SCAN(item['ip'],90,[80,8080]) 
	print "----------------------------------------------------------------------------"

# todo: 
# - SCAN return formatting
# - parsing user line args
# - output beautify - xml/html report format
# - 
####################################################################
#
# 	For future usage 
# - connection types
# - source/destination ip and ports
# - choosing timeout, interrupt and retrys between connections
# pinging using scapy port conn.
#
#####################################################################

#################################################
#
# classes for future usage
# SCAN_CLASS - main class creating all packet types  	
#
# methods:
#	def syn_scan:
#	def ack_scan:
#	def xmass_scan:
#	def full_scan:	
#
# ~end.



