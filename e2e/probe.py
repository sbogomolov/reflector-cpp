#!/usr/bin/env python3

from __future__ import annotations

import argparse
import binascii
import socket
import sys
import time


def parse_mac(value: str) -> bytes:
    parts = value.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}")

    try:
        octets = bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}") from exc

    if any(len(part) != 2 for part in parts):
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}")

    return octets


def magic_packet(mac: str) -> bytes:
    mac_bytes = parse_mac(mac)
    return b"\xff" * 6 + mac_bytes * 16


def parse_payload_hex(value: str) -> bytes:
    try:
        return binascii.unhexlify(value)
    except (binascii.Error, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"invalid hex payload: {value}") from exc


def packet_hex(payload: bytes) -> str:
    return binascii.hexlify(payload).decode("ascii")


def is_ipv6(address: str) -> bool:
    return ":" in address


def send(args: argparse.Namespace) -> int:
    payload = args.payload_hex if args.payload_hex is not None else magic_packet(args.mac)

    if is_ipv6(args.address):
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            scope_id = 0
            if args.interface:
                scope_id = socket.if_nametoindex(args.interface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope_id)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
            # The scope id in the address tuple disambiguates the link-local destination.
            sock.sendto(payload, (args.address, args.port, 0, scope_id))
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(payload, (args.address, args.port))

    print(f"sent {len(payload)} bytes to {args.address}:{args.port}: {packet_hex(payload)}", flush=True)
    return 0


def receive(args: argparse.Namespace) -> int:
    expected = None if args.expect_none else magic_packet(args.expect_mac)
    deadline = time.monotonic() + args.timeout

    family = socket.AF_INET6 if args.family == 6 else socket.AF_INET
    bind_address = "::" if family == socket.AF_INET6 else "0.0.0.0"

    with socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind_address, args.port))
        print(f"receiver ready: UDP socket bound on port {args.port}", flush=True)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            sock.settimeout(remaining)
            try:
                payload, peer = sock.recvfrom(4096)
            except TimeoutError:
                break

            print(f"received {len(payload)} bytes from {peer[0]}:{peer[1]}: {packet_hex(payload)}", flush=True)

            if args.expect_none:
                print("expected no packets, but one was received", file=sys.stderr, flush=True)
                return 1

            if payload == expected:
                return 0

            print("received payload does not match expected magic packet", file=sys.stderr, flush=True)
            return 1

    if args.expect_none:
        print(f"received no packets for {args.timeout:.3f}s", flush=True)
        return 0

    print(f"timed out waiting for expected packet after {args.timeout:.3f}s", file=sys.stderr, flush=True)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="UDP probe used by reflector Docker e2e tests")
    subparsers = parser.add_subparsers(dest="command", required=True)

    send_parser = subparsers.add_parser("send", help="send a Wake-on-LAN magic packet")
    payload = send_parser.add_mutually_exclusive_group(required=True)
    payload.add_argument("--mac", help="target MAC address")
    payload.add_argument("--payload-hex", type=parse_payload_hex, help="raw UDP payload encoded as hex")
    send_parser.add_argument("--port", required=True, type=int, help="destination UDP port")
    send_parser.add_argument("--address", default="255.255.255.255", help="destination IP address")
    send_parser.add_argument("--interface", help="egress interface (IPv6 link-local scope)")
    send_parser.set_defaults(func=send)

    receive_parser = subparsers.add_parser("receive", help="receive or reject UDP packets")
    receive_parser.add_argument("--port", required=True, type=int, help="UDP port to bind")
    receive_parser.add_argument("--timeout", required=True, type=float, help="seconds to wait")
    receive_parser.add_argument("--family", default=4, type=int, choices=(4, 6), help="IP version to bind")

    expectation = receive_parser.add_mutually_exclusive_group(required=True)
    expectation.add_argument("--expect-mac", help="MAC address whose magic packet must be received")
    expectation.add_argument("--expect-none", action="store_true", help="fail if any UDP packet is received")
    receive_parser.set_defaults(func=receive)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
