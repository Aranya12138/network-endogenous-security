#!/usr/bin/env python3
"""Send one fixed-size IPv4/UDP packet into the polymorphic domain."""

import argparse
import random
import sys

from scapy.all import Ether, IP, Raw, UDP, get_if_addr, get_if_hwaddr, get_if_list, sendp

POLY_UDP_PORT = 5000
PROTECTED_BYTES = 16


def get_if():
    for iface in get_if_list():
        if "eth0" in iface:
            return iface
    raise RuntimeError("Cannot find eth0 interface")


def encode_payload(message):
    raw = message.encode("utf-8")
    if len(raw) > PROTECTED_BYTES:
        raise ValueError("UTF-8 message must be at most 16 bytes")
    return raw.ljust(PROTECTED_BYTES, b"\x00")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", help="destination IPv4 address")
    parser.add_argument("message", help="UTF-8 text, at most 16 bytes")
    args = parser.parse_args()

    try:
        payload = encode_payload(args.message)
    except ValueError as exc:
        parser.error(str(exc))

    iface = get_if()
    source = get_if_addr(iface)
    packet = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
        / IP(src=source, dst=args.destination)
        / UDP(sport=random.randint(49152, 65535), dport=POLY_UDP_PORT)
        / Raw(load=payload)
    )
    sendp(packet, iface=iface, verbose=False)
    print(
        "POLY_SEND src=%s dst=%s dport=%d protected_hex=%s"
        % (source, args.destination, POLY_UDP_PORT, payload.hex())
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
