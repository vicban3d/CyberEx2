#!/usr/bin/python
import sys
from scapy.all import *
import os
from netfilterqueue import NetfilterQueue

# name of configurations file
conf_filename = 'conf'
# list of forbidden file extensions and related magic numbers
file_extensions = None
silent = False  # silent mode configuration
SSH_PORT = 22
TCP_SYN = 0x02
TCP_SYN_ACK = 0x12
TCP_ACK = 0x10
RST_FLAG = 0x04
MAX_FRAGMENT_CACHE = 10
MAX_CONNECTION_BUFFER_SIZE = 64
packet_buffer = {}
internal_nets = []

def handle_packet(pkt):
    global packet_buffer
    global internal_nets

    current_packet = IP(pkt.get_payload())
    dst_port = current_packet['TCP'].dport
    src_port = current_packet['TCP'].sport
    src_ip = current_packet['IP'].src
    dst_ip = current_packet['IP'].dst	    

    # check if new connection and initialize buffer
    if not existing_connection(src_ip, dst_ip, src_port, dst_port):
        # handle possible buffer overflow exploit
        if len(packet_buffer) > MAX_CONNECTION_BUFFER_SIZE:
            print '[WARNING] Connection buffer overflow, dropping all traffic.'
            pkt.drop()
            return
        else:
        	# initialize packet buffer.
            routing_tuple = str(src_ip) + '-' + str(dst_ip) + '-' + str(src_port) + '-' + str(dst_port)
            packet_buffer[routing_tuple] = {}

    routing_tuple = get_connection_key(src_ip, dst_ip, src_port, dst_port)
    # detected TCP traffic
    if IP in current_packet and TCP in current_packet:
        payload = current_packet['TCP'].payload       
        # if htere are more fragments and not enough collected yet, add to buffer. 
        if current_packet['IP'].flags == 1 and len(packet_buffer[routing_tuple]) <= MAX_FRAGMENT_CACHE:
            packet_buffer[routing_tuple][current_packet['TCP'].seq] = str(payload)
            payload_so_far = assemble_payload_fragments(packet_buffer[routing_tuple])  
        # if too many fragments colelcted, accept and reset buffer for current connection.
        elif len(packet_buffer[routing_tuple]) > MAX_FRAGMENT_CACHE:
            packet_buffer.pop(routing_tuple)
            pkt.accept()
            return
        else:
        	# else there is only one fragment which should be inspected.
        	payload_so_far = str(payload)
              
        # split TCP payload into parts (in case of HTTP traffic we will get
        # [METHOD] [PATH] [VERSION] at the beginning)
        header = payload_so_far.split(' ')
        # check for attempts to request a forbidden file
        if len(header) != 0 and header[0] == 'GET':
            path = header[1]
            # the file name is the last part of the path /a/b/c/file.x
            file_name = path.split('/')[len(path.split('/')) - 1]
            # the extension is the last part of the file name
            extension = file_name.split('.')[len(file_name.split('.')) - 1]

            # check if extension appears in the configuration file
            if extension in file_extensions:
                # send reset to client if not in silent mode
                if not silent:
                    send_reset(current_packet)
                print '[DROP] Request for a forbidden file extension (' \
                      + extension + ').'
                packet_buffer.pop(routing_tuple)
                pkt.drop()
            else:
                pkt.accept()
        else:  # request is TCP traffic but not HTTP GET request
            # check for ssh session attempts
            if dst_port == SSH_PORT and get_subnet_from_ip(
                    dst_ip) in internal_nets:
                # skip SYN and SYN,ACK packets to give the target node a chance
                # to refuse the connection gracefully
                if current_packet['TCP'].flags == TCP_SYN or \
                                current_packet['TCP'].flags == TCP_SYN_ACK:
                    pkt.accept()
                # catch the final ACK packet and block the SSH
                # connection by sending reset to both sides
                elif current_packet['TCP'].flags == TCP_ACK:
                    if not silent:
                        send_reset(current_packet)
                    print '[DROP] Attempt to establish SSH connection from', \
                        current_packet['IP'].src + '.'
                    packet_buffer.pop(routing_tuple)
                    pkt.drop()
                else:
                    pkt.accept()
            # if connection is not an SSH attempt, but an HTTP response
            # check if file extension in the body was spoofed (magic)
            elif payload_so_far[0:15] == 'HTTP/1.1 200 OK':
                body = payload_so_far.split('\r\n\r\n')[1]
                # convert body to HEX in order to compare the magic numbers
                body = str("".join("{:02x}".format(ord(c)) for c in body))
                # check if body starts with any forbidden magic number
                for magic in magic_numbers:
                    if body.lower().startswith(magic.lower()):
                        if not silent:
                            send_reset(current_packet)
                        print '[DROP] Attempt of file extension spoofing (' + \
                              file_extensions[
                                  magic_numbers.index(magic)] + ').'
                        packet_buffer.pop(routing_tuple)
                        pkt.drop()
                        return 
                packet_buffer.pop(routing_tuple)
                pkt.accept()
            else:
                packet_buffer.pop(routing_tuple)
                pkt.accept()
    else:
        pkt.accept()


# checks whether the current connection already exists in the packet buffer as a key.
def existing_connection(src_ip, dst_ip, src_port, dst_port):
	routing_tuple = str(src_ip) + '-' + str(dst_ip) + '-' + str(src_port) + '-' + str(dst_port)
	routing_tuple_reverse = str(dst_ip) + '-' + str(src_ip) + '-' + str(dst_port) + '-' + str(src_port)  
	return routing_tuple in packet_buffer.keys() or routing_tuple_reverse in packet_buffer.keys()

# returns the conenction key while disregarding direction(c2s/s2c).
def get_connection_key(src_ip, dst_ip, src_port, dst_port):
	routing_tuple = str(src_ip) + '-' + str(dst_ip) + '-' + str(src_port) + '-' + str(dst_port)
	if routing_tuple in packet_buffer.keys():
		return routing_tuple
	routing_tuple_reverse = str(dst_ip) + '-' + str(src_ip) + '-' + str(dst_port) + '-' + str(src_port)
	if routing_tuple_reverse in packet_buffer.keys():
		return routing_tuple_reverse

# returns the assembled packet from fragments received so far.
def assemble_payload_fragments(fragments):
	res = ''
	for seq in fragments.sort():
		res += fragments[seq]
	return res

# infers a subnet adddress from IP
def get_subnet_from_ip(ip):
    return ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[
        2] + '.0'

# returns a reset to the sender.
def send_reset(packet):
    dst_port = packet['TCP'].dport
    src_port = packet['TCP'].sport
    src_ip = packet['IP'].src
    dst_ip = packet['IP'].dst

    send(IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port,
                                          flags=RST_FLAG,
                                          seq=packet['TCP'].ack),
         verbose=False)
    send(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port,
                                          flags=RST_FLAG,
                                          seq=packet['TCP'].seq),
         verbose=False)


if __name__ == '__main__':  
    # place all packets marked for forwarding in queue
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')

    # read configuration file
    with open(conf_filename) as f:
        config = map(str.strip, f.readlines())
    # read silent mode config
    silent = True if config[0].split('=')[1] == '1' else False
    # skip to files
    config = config[2:]
    magic_numbers = filter(lambda mnum: mnum != '', [cur.split('-')[1] for cur in config])
    file_extensions = [x.split('-')[0] for x in config]

    print 'Started Packet Filter in ' + (
        'silent ' if silent else 'loud ') + 'mode.'

    # discover all internal subnets to detect connection
    # attempts to an internal node

    # get addresses of all gateway interfaces
    addresses = [get_if_addr(i) for i in get_if_list()]
    # infer subnets from addresses
    for addr in addresses:
        internal_nets.append(get_subnet_from_ip(addr))

    # start catching packets
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, handle_packet)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        os.system('iptables -F')
        os.system('iptables -X')
