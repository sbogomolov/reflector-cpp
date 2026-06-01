#!/usr/bin/env python3
"""Sustained mDNS + SSDP load generator for the valgrind soak.

Sends mDNS queries (exercises the stateless hot relay path) and SSDP M-SEARCHes from a ROTATING
source port (each distinct (ip, port) makes the reflector create a fresh Session, so this drives the
session create/evict churn the leak hunt cares about). MX is 1s so sessions expire fast and the
table constantly fills to its 32 cap and evicts — maximizing create/destroy cycles per minute.
"""

from __future__ import annotations

import argparse
import socket
import struct
import time

MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()
MDNS_QUERY = bytes.fromhex("00000000000100000000000074657374")

SSDP_GROUP = "239.255.255.250"
MDNS_GROUP = "224.0.0.251"


def main() -> int:
    ap = argparse.ArgumentParser(description="mDNS/SSDP flood for the valgrind soak")
    ap.add_argument("--interface", required=True, help="egress interface for multicast")
    ap.add_argument("--duration", type=float, default=90.0, help="seconds to flood")
    ap.add_argument("--interval", type=float, default=0.05, help="seconds between iterations")
    ap.add_argument("--base-port", type=int, default=20000, help="first rotating SSDP source port")
    ap.add_argument("--ports", type=int, default=64, help="how many source ports to rotate through")
    args = ap.parse_args()

    ifindex = socket.if_nametoindex(args.interface)
    mreqn = struct.pack("@4s4si", b"\x00\x00\x00\x00", b"\x00\x00\x00\x00", ifindex)

    mdns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    mdns.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    mdns.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)

    print(f"flood: if={args.interface} duration={args.duration}s interval={args.interval}s "
          f"ports={args.base_port}..{args.base_port + args.ports - 1}", flush=True)

    end = time.monotonic() + args.duration
    i = 0
    msearch_sent = 0
    mdns_sent = 0
    while time.monotonic() < end:
        sport = args.base_port + (i % args.ports)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", sport))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            s.sendto(MSEARCH, (SSDP_GROUP, 1900))
            s.close()
            msearch_sent += 1
        except OSError:
            pass  # a rotating port still in use from a prior iteration; skip it

        mdns.sendto(MDNS_QUERY, (MDNS_GROUP, 5353))
        mdns_sent += 1

        i += 1
        if i % 200 == 0:
            print(f"flood: {msearch_sent} M-SEARCH, {mdns_sent} mDNS sent", flush=True)
        time.sleep(args.interval)

    print(f"flood done: {msearch_sent} M-SEARCH, {mdns_sent} mDNS queries sent", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
