#! /usr/bin/python
"""
cyber assignment 2 question 2 client
"""
import hmac
import sys
import argparse
from scapy.layers.inet import IP, TCP
from scapy.all import  sr1, send
from hashlib import sha256
import random

KEY = "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def send_hmac_msg(args):
    """
    send hmac message
    """
    src_ip = args.src
    dst_ip = args.dst
    random_port = random.randint(1024, 65535)

    ip_pkt = IP(src=src_ip, dst=dst_ip)
    tcp_pkt = TCP(dport=8080, sport=random_port, \
        seq=random.randint(0, 100000), flags='S')
    syn_ack = sr1(ip_pkt / tcp_pkt)

    print "Got SYN+ACK, returning ACK..."

    tcp_pkt = TCP(dport=8080, sport=random_port, \
    seq=syn_ack[TCP].ack, ack=(syn_ack[TCP].seq + 1), flags='A')
    send(ip_pkt / tcp_pkt)

    hmac_msg = hmac.new(KEY, args.msg, sha256).digest()
    http_msg = "GET / HTTP/1.1\r\nContent-Length: " + \
    str(len(hmac_msg)+len(args.msg)) + "\r\n\r\n" + hmac_msg + args.msg

    sr1(ip_pkt / tcp_pkt / http_msg, timeout=30)

    exit()


if __name__ == '__main__':
    if len(sys.argv) not in range(4, 5):
        exit('Invalid arguments!')

    PARS = argparse.ArgumentParser()
    PARS.add_argument('-src', help="Source IP")
    PARS.add_argument('-dst', help="Destination IP")
    PARS.add_argument('-msg', help="HTTP message")
    send_hmac_msg(PARS.parse_args())
