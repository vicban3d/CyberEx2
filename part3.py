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
		dst_port = scapy_packet['TCP'].dport
		src_port = scapy_packet['TCP'].sport
		src_ip = scapy_packet['IP'].src
		dst_ip = scapy_packet['IP'].dst


		payload  = scapy_packet[TCP].payload		
		header = str(payload).split(' ')

		# Check for attempts to request a forbidden file
		if len(header) != 0 and header[0] == 'GET':
			path = header[1]
			filename = path.split('/')[len(path.split('/')) - 1]
			extension = filename.split('.')[len(filename.split('.')) - 1]
			if extension in blacklist:
				if not silent:					
					print 'Detected request for', extension, 'file. ACTION: DROP'
					response = scapy_packet
					response['TCP'].dport = src_port
					response['TCP'].sport = dst_port
					response['IP'].src = dst_ip
					response['IP'].dst = src_ip
					response['TCP'].flags = 'R'					
					del response['IP'].chksum
					send(response)
				pkt.accept()		
			else:
				pkt.accept()		
		else:						
			# Discover all subnets
			internal_nets = []
			addresses = [get_if_addr(i) for i in get_if_list()]
			for addr in addresses:
				internal_nets.append(get_subnet_from_ip(addr))
			
			# Check for ssh session attempts
			if dst_port == SSH_PORT and get_subnet_from_ip(dst_ip) in internal_nets:
				print 'FLAGS', scapy_packet['TCP'].flags
				if scapy_packet['TCP'].flags == 0x02 or scapy_packet['TCP'].flags == 0x12:
					pkt.accept()
				elif scapy_packet['TCP'].flags == 0x10:					
					if not silent:					
						send(IP(src=dst_ip, dst=src_ip)/TCP(sport=dst_port, dport=src_port, flags=0x04, seq=1))
					pkt.drop()					
				else:
					pkt.accept()
			# Check if file extension was spoofed (magic)
			elif str(payload)[0:15] == 'HTTP/1.1 200 OK':
				data = str(payload).split('\r\n\r\n')[1]
				data = str("".join("{:02x}".format(ord(c)) for c in data))

				for magic in magic_numbers:					
					cut = (data[0:len(magic)])
					if cut.lower() == magic.lower():
						print 'Detected attempt of file extension spoofing. ACTION: DROP'
						pkt.drop()
						return
				pkt.accept()
			else:				
				pkt.accept()
	else:
		pkt.accept()

def get_subnet_from_ip(ip):
	return ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[2] + '.0'


if __name__ == '__main__':
	os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')
	# read conf
	with open(conf_filename) as f:
		config = map(str.strip, f.readlines())

	silent = True if config[0].split('=')[1] == '1' else False
	blacklist = config[config.index('#Blocked File Extensions:')+1:]
	magic_numbers = [x.split('-')[1] for x in blacklist]
	magic_numbers = filter(lambda x : x != '', magic_numbers)
	blacklist = [x.split('-')[0] for x in blacklist]
	print 'Started Packet Filter in ' + ('silent ' if silent else 'loud ') + 'mode.'

	nfqueue = NetfilterQueue()
	nfqueue.bind(1, handle_packet)
	try:
		nfqueue.run()
	except KeyboardInterrupt:
		os.system('iptables -F')
		os.system('iptables -X')
