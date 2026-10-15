#!/usr/bin/env python3
"""Receive adjudicated IPv4/UDP packets and enforce an expected count."""

import argparse
import os
import sys

from scapy.all import IP, Raw, UDP, sniff

POLY_UDP_PORT = 5000
PROTECTED_BYTES = 16


def get_if():
    interfaces = sorted(i for i in os.listdir("/sys/class/net") if "eth" in i)
    if not interfaces:
        raise RuntimeError("Cannot find an Ethernet interface")
    return interfaces[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=4.0)
    parser.add_argument("--expect", type=int, default=1)
    args = parser.parse_args()

    iface = get_if()
    received = []

    def is_poly_result(packet):
        return IP in packet and UDP in packet and packet[UDP].dport == POLY_UDP_PORT

    def handle(packet):
        payload = bytes(packet[Raw].load) if Raw in packet else b""
        protected = payload[:PROTECTED_BYTES]
        received.append(protected)
        print(
            "POLY_RECV index=%d src=%s dst=%s ttl=%d protected_hex=%s text=%r"
            % (
                len(received),
                packet[IP].src,
                packet[IP].dst,
                packet[IP].ttl,
                protected.hex(),
                protected.rstrip(b"\x00").decode("utf-8", errors="replace"),
            ),
            flush=True,
        )

    print(
        "POLY_LISTEN iface=%s timeout=%.1f expect=%d" % (iface, args.timeout, args.expect),
        flush=True,
    )
    sniff(
        iface=iface,
        timeout=args.timeout,
        lfilter=is_poly_result,
        prn=handle,
        stop_filter=lambda _packet: args.expect > 0 and len(received) >= args.expect,
        store=False,
    )
    print("POLY_SUMMARY received=%d expected=%d" % (len(received), args.expect), flush=True)
    return 0 if len(received) == args.expect else 1


if __name__ == "__main__":
    sys.exit(main())
