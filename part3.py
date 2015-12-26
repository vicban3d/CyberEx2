#!/usr/bin/python
from scapy.all import *
import os
import socket
from netfilterqueue import NetfilterQueue
import re

# name of configurations file
conf_filename = 'conf'
# list of forbidden file extensions
blacklist = None
# silent mode configuration
silent = None
SSH_PORT = 22

def handle_packet(pkt):
	global response
	scapy_packet = IP(pkt.get_payload())
	
	if IP in scapy_packet and TCP in scapy_packet: 
		
		payload  = scapy_packet[TCP].payload		
		header = str(payload).split(' ')

		if len(header) != 0 and header[0] == 'GET':
			path = header[1]
			filename = path.split('/')[len(path.split('/')) - 1]
			extension = filename.split('.')[len(filename.split('.')) - 1]
			if extension in blacklist:
				if not silent:					
					print 'Detected request for', extension, 'file. ACTION: DROP'
				pkt.accept()	
			else:
				pkt.accept()		
		else:
			dst_port = scapy_packet['TCP'].dport
			src_ip = scapy_packet['IP'].src
			dst_ip = scapy_packet['IP'].dst			
			
			# *** DISCOVER LOCAL SUBNETS *** #
			internal_nets = []
			addresses = [get_if_addr(i) for i in get_if_list()]
			for addr in addresses:
				addr = addr.split('.')[0] + '.' + addr.split('.')[1] + '.' + addr.split('.')[2] + '.0'		
				internal_nets.append(addr)
			
			dst_net = dst_ip.split('.')[0] + '.' + dst_ip.split('.')[1] + '.' + dst_ip.split('.')[2] + '.0'
			src_net = src_ip.split('.')[0] + '.' + src_ip.split('.')[1] + '.' + src_ip.split('.')[2] + '.0'

			if dst_port == SSH_PORT and dst_net in internal_nets:
				if not silent:
					print 'Detected remote shell execution attempt from', src_ip ,'. ACTION: DROP'
				pkt.drop()				
			else:
				pkt.accept()
	else:
		pkt.accept()


if __name__ == '__main__':
	os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')
	# read conf
	with open(conf_filename) as f:
		config = map(str.strip, f.readlines())

	silent = True if config[0].split('=')[1] == '1' else False
	blacklist = config[config.index('#Blocked File Extensions:')+1:]

	print 'Started Packet Filter in ' + ('silent ' if silent else 'loud ') + 'mode.'

	nfqueue = NetfilterQueue()
	nfqueue.bind(1, handle_packet)
	try:
		nfqueue.run()
	except KeyboardInterrupt:
		os.system('iptables -F')
		os.system('iptables -X')
