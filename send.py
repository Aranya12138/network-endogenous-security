#!/usr/bin/env python3
import sys
import socket
import random

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, IPv6, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():
    # IPv4: python3 send.py <dst_ip> "<message>" 
    # IPv6: python3 send.py <src_ip> <dst_ip> "<message>" 
    
    if len(sys.argv) == 3:
        # IPv4
        dst_addr_str = sys.argv[1]
        payload = sys.argv[2]
        src_addr = None # 
        
        try:
            # IPv4
            dst_addr = socket.gethostbyname(dst_addr_str)
        except socket.gaierror:
            print(f"Error: Invalid IPv4 address or hostname: {dst_addr_str}")
            sys.exit(1)

        print(f"Sending IPv4 packet to {dst_addr}")
        ip_layer = IP(dst=dst_addr)
        
    elif len(sys.argv) == 4:
        # IPv6
        src_addr = sys.argv[1]
        dst_addr = sys.argv[2]
        payload = sys.argv[3]

        print(f"Sending IPv6 packet from {src_addr} to {dst_addr}")
        ip_layer = IPv6(src=src_addr, dst=dst_addr)
        
    else:
        print('Usage for IPv4: python3 send.py <destination_ip> "<message>"')
        print('Usage for IPv6: python3 send.py <source_ip> <destination_ip> "<message>"')
        exit(1)

    iface = get_if()
    sport = random.randint(49152, 65535)
    
    print(f"On interface {iface}")

    eth_layer = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    transport_layer = UDP(dport=1234, sport=sport)
        
    pkt = eth_layer / ip_layer / transport_layer / payload
    
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
