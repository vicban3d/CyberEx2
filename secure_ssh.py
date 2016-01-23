#!/usr/bin/python
'''
This script enables secure SSH authentication.
'''


from scapy.all import conf

# name of configurations file
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send
import os
from netfilterqueue import NetfilterQueue
from hashlib import sha256

import hmac

os.system('iptables -A OUTPUT -j NFQUEUE --queue-num 1')
KEY = "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
COUNTER = 42
SSH_PORT = 22
TCP_ACK = 0x10
TCP_SYN = 0x02
SEQ = 0

def handle_packet(pkt):
    """
    Handles user SSH requests and authentication
    """
    global COUNTER
    global SEQ
    sent_packet = IP(pkt.get_payload())

    if IP in sent_packet and TCP in sent_packet and \
    	sent_packet['TCP'].flags == TCP_SYN:
        SEQ = sent_packet['TCP'].seq + 1
        pkt.accept()

    elif IP in sent_packet and TCP in sent_packet and \
    	sent_packet['TCP'].flags == TCP_ACK and \
    	sent_packet['TCP'].dport == SSH_PORT and \
    	sent_packet['TCP'].seq == SEQ:
        encrypted_salt = hmac.new(KEY, str(COUNTER), sha256).digest()
        COUNTER += 1

        ip_pkt = IP(src=sent_packet[IP].src, dst=sent_packet[IP].dst)
        tcp_pkt = TCP(dport=SSH_PORT, sport=sent_packet[TCP].sport, \
        seq=sent_packet[TCP].seq, ack=(sent_packet[TCP].ack), flags='A')

        # send http message
        sent_packet = ip_pkt / tcp_pkt / encrypted_salt
        send(sent_packet)

        pkt.drop()
        print "[PROTECTED]", sent_packet['IP'].src
    else:
        pkt.accept()


if __name__ == '__main__':
    print r"""
 _________________________ 
|<><><>     |  |    <><><>|
|<>         |  |        <>|
|           |  |          |
|  (______ <\-/> ______)  |
|  /_.-=-.\| " |/.-=-._\  | 
|~  /_    \(o_o)/    _\  ~|
|~~  /_  /\/ ^ \/\  _\  ~~|
|~~~   \/ | / \ | \/   ~~~|
|_______ /((( )))\ _______|
|      __\ \___/ /__      |
|~~~ (((---'   '---))) ~~~|
|~~         |  |        ~~|
|~          |  |         ~|
:           |  |          :     
 \<>        |  |       <>/      
  \<>       |  |      <>/       
   \<>      |  |     <>/       
    `\<>    |  |   <>/'         
      `\<>  |  |  <>/'         
        `\<>|  |<>/'         
          `-.  .-`           
            '--'
         SECURE SSH"""
    NFQUEUE = NetfilterQueue()
    NFQUEUE.bind(1, handle_packet)
    try:
        NFQUEUE.run()
    except KeyboardInterrupt:
        os.system('iptables -F')
        os.system('iptables -X')
