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
MAX_FRAGMENT_CACHE = 4
MAX_CONNECTION_BUFFER_SIZE = 64
packet_buffer = {}
fragment_number = 0
internal_nets = []


def handle_packet(pkt):
    global packet_buffer
    global fragment_number
    global internal_nets

    current_packet = IP(pkt.get_payload())
    dst_port = current_packet['TCP'].dport
    src_port = current_packet['TCP'].sport
    src_ip = current_packet['IP'].src
    dst_ip = current_packet['IP'].dst

    # identifier for the current packet
    routing_tuple = str(src_ip) + '-' + str(dst_ip) + '-' + str(
        src_port) + '-' + str(dst_port)
    routing_tuple_reverse = str(dst_ip) + '-' + str(src_ip) + '-' + str(
        dst_port) + '-' + str(src_port)

    # check if new connection and initialize buffer
    if routing_tuple not in packet_buffer.keys():
        # handle possible buffer overflow exploit
        if len(packet_buffer) > MAX_CONNECTION_BUFFER_SIZE:
            print '[WARNING] Connection buffer overflow, dropping all traffic.'
            pkt.drop()
            return
        else:
            packet_buffer[routing_tuple] = ''
            packet_buffer[routing_tuple_reverse] = ''

    # detected TCP traffic
    if IP in current_packet and TCP in current_packet:
        payload = current_packet['TCP'].payload
        packet_buffer[routing_tuple] += str(payload)
        if current_packet['IP'].flags == 1 and fragment_number \
                <= MAX_FRAGMENT_CACHE:
            fragment_number += 1
        elif fragment_number > MAX_FRAGMENT_CACHE:
            fragment_number = 0
            packet_buffer.pop(routing_tuple)
            packet_buffer.pop(routing_tuple_reverse)
            pkt.accept()
            return

        # split TCP payload into parts (in case of HTTP traffic we will get
        # [METHOD] [PATH] [VERSION] at the beginning)
        header = packet_buffer[routing_tuple].split(' ')
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
                packet_buffer.pop(routing_tuple_reverse)

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
                    packet_buffer.pop(routing_tuple_reverse)
                    pkt.drop()
                else:
                    pkt.accept()
            # if connection is not an SSH attempt, but an HTTP response
            # check if file extension in the body was spoofed (magic)
            elif packet_buffer[routing_tuple][0:15] == 'HTTP/1.1 200 OK':
                body = packet_buffer[routing_tuple].split('\r\n\r\n')[1]
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
                        packet_buffer.pop(routing_tuple_reverse)
                        pkt.drop()
                        return
                if fragment_number == 0:
                    packet_buffer.pop(routing_tuple)
                    packet_buffer.pop(routing_tuple_reverse)
                pkt.accept()
            else:
                if fragment_number == 0:
                    packet_buffer.pop(routing_tuple)
                    packet_buffer.pop(routing_tuple_reverse)
                pkt.accept()
    else:
        pkt.accept()


def get_subnet_from_ip(ip):
    return ip.split('.')[0] + '.' + ip.split('.')[1] + '.' + ip.split('.')[
        2] + '.0'


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
    # global internal_nets
    # process commandline arguments
    if len(sys.argv) == 1:
        silent = False
    elif len(sys.argv) == 2:
        if sys.argv[1] == '-s':
            silent = True
        else:
            print 'Usage: part3.py [-s]\n\t[-s] - Silent Mode: Client will' \
                  ' not be notified of blocked traffic.'
            exit()
    else:
        print 'Usage: part3.py [-s]\n\t[-s] - Silent Mode: Client will' \
              ' not be notified of blocked traffic.'
        exit()

    # place all packets marked for forwarding in queue
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')

    # read configuration file
    with open(conf_filename) as f:
        config = map(str.strip, f.readlines())
    magic_numbers = filter(lambda mnum: mnum != '',
                           [cur.split('-')[1] for cur in config])
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
