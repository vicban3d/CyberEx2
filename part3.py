#!/usr/bin/python

"""
Cyber Assignment 2, part 3.
Authors: Victor Banshats and Zvi Azran

Algorithm for file blocking:

    The algorithm looks at two approaches:

    Firstly, if the client request a file via HTTP the file
    extension is examined through the GET [path] [version]
    header. If the file contains a forbidden extension the
    packet is dropped.

    Secondly, the algorithm detects fake file extensions on
    received files. If the client requests a legitimate file
    the algorithm examines the received HTTP response. if
    the content of the '200 OK' message's body starts with a
    magic identifier of one of the forbidden files the response
    is dropped.

    All file extensions and corresponding magic identifiers
    are specified in the configuration file.

Algorithm for port knocking:

    Before an SSH connection is allowed it must exist in the
    ALLOWED_SSH_CONNECTIONS list.
    To be inserted into the list the client must send a ping with
    payload size of THE_ANSWER_TO_LIFE_THE_UNIVERSE_AND_EVERYTHING.

    Dealing with replay attacks:

    An attacker may sniff the client's traffic and replay it,
    including the secret ping key as mentioned above. To deal
    with this, the ICMP id field is stored along side the
    connection with the assumption that the same id cannot be
    sent from the same client over two different ping requests.
    If a ping from an allowed client with the allowed id is
    received again, the packet is dropped.

    Dealing with spoofing:

    When a client connects via SSH his connection id from the IP
    layer is stored along side his ip address. If an attacker attempts
    to connect with the same IP address his id will not match the
    id of the true connection. The algorithm constantly keeps track
    of the progressing id number to minimize the chance of id spoofing.

    Once the client disconnects from the SSH session he will not be
    allowed to start another before he performs the port knocking
    procedure again.

    Known vulnerability:
        If the client sends the correct ping, an attacker may use the time
        window between the recieving of the ping and the initiation of the
        SSH conenction by the client to hijack the permission and establish
        an SSH connection with a spoofed IP address. In this case the client
        will be blocked by the GW.

    attached pcap files:
        ssh_success.pcap
        ssh_fail.pcap
        ssh_spoofing.pcap

"""

import os
from netfilterqueue import NetfilterQueue

from scapy.all import conf

# name of configurations file
from scapy.layers.inet import IP, TCP, ICMP
from scapy.sendrecv import send

CONF_FILENAME = 'conf'  # name of configuration file
# list of forbidden file extensions and related magic numbers
FILE_EXTENSIONS = None
SILENT = False  # silent mode configuration
SSH_PORT = 22
HTTP_PORTS = [80, 8080, 443]
# flag codes
TCP_SYN = 0x02
TCP_SYN_ACK = 0x12
TCP_ACK = 0x10
RST_FLAG = 0x04
FIN_FLAG = 0x11
MF_FLAG = 1
# buffers
MAX_FRAGMENT_CACHE = 4
MAX_CONNECTION_BUFFER_SIZE = 64
THE_ANSWER_TO_LIFE_THE_UNIVERSE_AND_EVERYTHING = 42
PACKET_BUFFER = {}
ALLOWED_SSH_CONNECTIONS = {}
SSH_CONNECTION_ID = {}
FIN_RECEIVED = False


def handle_packet(pkt):
    """
    Handles traffic and decides whether to accept or drop it.
    :param pkt: the packet received from nfqueue
    :return: None
    """

    global FIN_RECEIVED

    # a scapy representation of the received packet
    current_packet = IP(pkt.get_payload())

    # check if connection is TCP
    if IP in current_packet and TCP in current_packet:
        # get connection parameters
        dst_port = current_packet['TCP'].dport
        src_port = current_packet['TCP'].sport
        src_ip = current_packet['IP'].src
        dst_ip = current_packet['IP'].dst

        # generate conenction identifier
        routing_tuple = get_connection_key(src_ip, dst_ip, src_port, dst_port)
        # accept connection syn attempts to allow dst to refuse gracefully
        if current_packet['TCP'].flags == TCP_SYN:
            pkt.accept()
        # if there was an answer to the syn save the conenction
        elif current_packet['TCP'].flags == TCP_SYN_ACK:
            # if the connection doesn't exist yet
            if not existing_connection(src_ip, dst_ip, src_port, dst_port):
                # prevent possible buffer overflow
                if len(PACKET_BUFFER) > MAX_CONNECTION_BUFFER_SIZE:
                    print '[WARNING] Connection buffer overflow, ' \
                          'dropping all traffic.'
                    pkt.drop()
                else:
                    # initialize packet buffer
                    PACKET_BUFFER[routing_tuple] = {}
                    pkt.accept()
            else:
                # otherwise accept the connection
                pkt.accept()
        # if the connection is an SSH attempt and it is established
        elif dst_port == SSH_PORT and \
                existing_connection(src_ip, dst_ip, src_port, dst_port):
            # block the connection final ack and send reset of disallowed
            if current_packet['TCP'].flags == TCP_ACK and \
                            src_ip not in ALLOWED_SSH_CONNECTIONS \
                    and FIN_RECEIVED is False:
                if not SILENT:
                    send_reset(current_packet)
                print '[DROP] Attempt to establish SSH connection from', \
                    current_packet['IP'].src + '.'
                PACKET_BUFFER.pop(routing_tuple)
                pkt.drop()
            elif current_packet['TCP'].flags == TCP_ACK and src_ip not \
                    in SSH_CONNECTION_ID.keys():
                if FIN_RECEIVED is False:
                    # if allowed, accept the connection
                    SSH_CONNECTION_ID[src_ip] = current_packet['IP'].id
                else:
                    FIN_RECEIVED = False
                pkt.accept()
            elif current_packet['TCP'].flags == FIN_FLAG and src_ip \
                    in SSH_CONNECTION_ID.keys():
                SSH_CONNECTION_ID.pop(src_ip)
                pkt.accept()
                FIN_RECEIVED = True
                ALLOWED_SSH_CONNECTIONS.pop(src_ip)
            else:
                if SSH_CONNECTION_ID[src_ip] == current_packet['IP'].id - 1:
                    SSH_CONNECTION_ID[src_ip] = current_packet['IP'].id
                    pkt.accept()
                else:
                    if not SILENT:
                        send_reset(current_packet)
                    print '[DROP] Attempt of IP spoofing', \
                        current_packet['IP'].src + '.'
                    pkt.drop()
        # if the connection is an HTTP request or response and is established
        elif (src_port in HTTP_PORTS or dst_port in HTTP_PORTS) and \
                existing_connection(src_ip, dst_ip, src_port, dst_port):
            payload = current_packet['TCP'].payload
            # if there are more fragments and not enough
            # collected yet, add to buffer
            if current_packet['IP'].flags == MF_FLAG \
                    and len(PACKET_BUFFER[routing_tuple]) <= MAX_FRAGMENT_CACHE:
                PACKET_BUFFER[routing_tuple][current_packet['TCP'].seq] = \
                    str(payload)
                payload_so_far = \
                    assemble_payload_fragments(PACKET_BUFFER[routing_tuple])
            # if too many fragments collected, accept and
            # reset buffer for current connection.
            elif len(PACKET_BUFFER[routing_tuple]) > MAX_FRAGMENT_CACHE:
                PACKET_BUFFER.pop(routing_tuple)
                pkt.accept()
                return
            else:
                # else there is only one fragment which should be inspected.
                payload_so_far = str(payload)

            # check for attempts to request a forbidden file
            if dst_port in HTTP_PORTS:
                if current_packet['TCP'].flags == TCP_ACK:
                    pkt.accept()
                    return
                # split TCP payload into parts
                # in case of HTTP traffic we will get
                # [METHOD] [PATH] [VERSION] at the beginning
                header = payload_so_far.split(' ')
                if len(header) != 0 and header[0] == 'GET':
                    # the file name is the last part of the path /a/b/c/file.x
                    file_name = \
                        header[1].split('/')[len(header[1].split('/')) - 1]
                    # the extension is the last part of the file name
                    extension = \
                        file_name.split('.')[len(file_name.split('.')) - 1]

                    # check if extension appears in the configuration file
                    if extension in FILE_EXTENSIONS:
                        # send reset to client if not in silent mode
                        if not SILENT:
                            send_reset(current_packet)
                        print '[DROP] Request for a forbidden file extension ' \
                              '(' + extension + ').'
                        PACKET_BUFFER.pop(routing_tuple)
                        pkt.drop()
                    else:
                        # file extension is allowed
                        pkt.accept()
                else:
                    # not a GET request
                    pkt.accept()
            # id packet is an HTTP response check for extension spoofing
            elif src_port in HTTP_PORTS and payload_so_far[0:15] == \
                    'HTTP/1.1 200 OK':
                body = payload_so_far.split('\r\n\r\n')[1]
                # convert body to HEX in order to compare the magic numbers
                body = str("".join("{:02x}".format(ord(c)) for c in body))
                # check if body starts with any forbidden magic number
                for magic in MAGIC_NUMBERS:
                    if body.lower().startswith(magic.lower()):
                        if not SILENT:
                            send_reset(current_packet)
                        print '[DROP] Attempt of file extension spoofing (' + \
                              FILE_EXTENSIONS[MAGIC_NUMBERS.index(magic)] + ').'
                        PACKET_BUFFER.pop(routing_tuple)
                        pkt.drop()
                        return
                # accept file if the spoofed extension is allowed
                PACKET_BUFFER.pop(routing_tuple)
                pkt.accept()
            else:
                # neither src port nor dst port are http (failsafe else)
                pkt.accept()
        else:
            # connection is neither SSH nor HTTP
            pkt.accept()
    # check for port knocking attempt. SSH will open of payload size is right
    elif IP in current_packet and ICMP in current_packet:
        icmp = current_packet['ICMP']
        if len(icmp.load) == THE_ANSWER_TO_LIFE_THE_UNIVERSE_AND_EVERYTHING:
            src_ip = current_packet['IP'].src
            if len(ALLOWED_SSH_CONNECTIONS) >= MAX_CONNECTION_BUFFER_SIZE:
                ALLOWED_SSH_CONNECTIONS.clear()
            # two pings from the same client will have different ids
            # if existing id found it is most likely a replay attack
            if src_ip in ALLOWED_SSH_CONNECTIONS.keys() \
                    and ALLOWED_SSH_CONNECTIONS[src_ip] \
                            == current_packet['ICMP'].id:
                print '[DROP] Attempt of traffic replay.'
                pkt.drop()
            else:
                # add ip to allowed ssh connections
                ALLOWED_SSH_CONNECTIONS[src_ip] = current_packet['ICMP'].id
            # accept in any case
            pkt.accept()
    else:
        # packet is neither TCP nor ICMP
        pkt.accept()


def existing_connection(src_ip, dst_ip, src_port, dst_port):
    """
    Checks whether the given parameters represent an
    already existing connection
    :param src_ip: source OP
    :param dst_ip: destination ip
    :param src_port: source port
    :param dst_port: destination port
    :return: True / False
    """
    routing_tuple = str(src_ip) + '-' + str(dst_ip) + '-' + str(
            src_port) + '-' + str(dst_port)
    routing_tuple_reverse = str(dst_ip) + '-' + str(src_ip) + '-' + str(
            dst_port) + '-' + str(src_port)
    return routing_tuple in PACKET_BUFFER.keys() \
           or routing_tuple_reverse in PACKET_BUFFER.keys()


def get_connection_key(src_ip, dst_ip, src_port, dst_port):
    """
    returns the connection key while disregarding direction(c2s/s2c)
    :param src_ip: source OP
    :param dst_ip: destination ip
    :param src_port: source port
    :param dst_port: destination port
    :return: a tuple representing the connection identifier.
    """
    routing_tuple = str(src_ip) + '-' + str(dst_ip) + '-' + str(
            src_port) + '-' + str(dst_port)
    routing_tuple_reverse = str(dst_ip) + '-' + str(src_ip) + '-' + str(
            dst_port) + '-' + str(src_port)
    if routing_tuple_reverse in PACKET_BUFFER.keys():
        return routing_tuple_reverse
    else:
        return routing_tuple


# returns the assembled packet from fragments received so far.
def assemble_payload_fragments(fragments):
    """
    assembles fragments and returns the complete data
    :param fragments: a list of all fragments
    :return: assembled payload
    """
    res = ''
    for seq in fragments.sort():
        res += fragments[seq]
    return res


# returns a reset to the sender.
def send_reset(original_packet):
    """
    sends a reset message to both parties of a connection
    :param original_packet: the packet that the reset repies to
    :return: None
    """
    dst_port = original_packet['TCP'].dport
    src_port = original_packet['TCP'].sport
    src_ip = original_packet['IP'].src
    dst_ip = original_packet['IP'].dst

    send(IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port,
                                          flags=RST_FLAG,
                                          seq=original_packet['TCP'].ack),
         verbose=False)
    send(IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port,
                                          flags=RST_FLAG,
                                          seq=original_packet['TCP'].seq),
         verbose=False)


if __name__ == '__main__':
    # place all packets marked for forwarding in queue
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')

    # read configuration file
    with open(CONF_FILENAME) as f:
        CONFIG_FILE = [str.strip(x) for x in f.readlines()]
    # read silent mode config
    SILENT = True if CONFIG_FILE[0].split('=')[1] == '1' else False
    # skip to files
    CONFIG_FILE = CONFIG_FILE[2:]
    MAGIC_NUMBERS = [x for x in [cur.split('-')[1] for cur in CONFIG_FILE]
                     if x != '']

    FILE_EXTENSIONS = [x.split('-')[0] for x in CONFIG_FILE]

    print 'Started Packet Filter in ' + (
        'silent ' if SILENT else 'loud ') + 'mode.'

    # start catching packets
    NFQUEUE = NetfilterQueue()
    NFQUEUE.bind(1, handle_packet)
    try:
        NFQUEUE.run()
    except KeyboardInterrupt:
        os.system('iptables -F')
        os.system('iptables -X')
