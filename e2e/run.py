#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ast
import dataclasses
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
E2E_DIR = Path(__file__).resolve().parent

DEFAULT_REFLECTOR_IMAGE = "reflector:e2e"
VALGRIND_REFLECTOR_IMAGE = "reflector:e2e-valgrind"
DEFAULT_HELPER_IMAGE = "python:3.13-alpine"
CONFIGURED_MAC = "02:42:ac:11:00:09"
WRONG_MAC = "02:42:ac:11:00:0a"
CONFIGURED_PORT = 40009
UNCONFIGURED_PORT = 40010
ANY_MAC_PORT = 40011
MALFORMED_MAGIC_PAYLOAD_HEX = "ff" * 6 + "0242ac11000a" * 15 + "0242ac11000b"
REFLECTOR_READY_LOG = "Starting dispatcher event loop"
RECEIVER_READY_LOG = "receiver ready: UDP socket bound"
CONTAINER_READY_TIMEOUT_SECONDS = 15.0
# A clean SIGTERM exit triggers valgrind's leak analysis; give `docker stop` this much grace to let it
# finish, since SIGKILLing it mid-analysis would surface as a (false) finding.
VALGRIND_STOP_GRACE_SECONDS = 60
REFLECTOR_SOURCE_IFNAME = "wol_src"
REFLECTOR_TARGET_IFNAME = "wol_dst"
RECEIVER_IFNAME = "probe0"

MDNS_GROUP_V4 = "224.0.0.251"
MDNS_GROUP_V6 = "ff02::fb"
MDNS_PORT = 5353
# A non-mDNS UDP port: the reflector's filter keys on dest_port 5353, so a datagram to the group on
# this port is captured by the BPF but never dispatched to the reflector.
MDNS_WRONG_PORT = 5354
# Minimal mDNS messages: a 12-byte DNS header plus a 4-byte "test" tail (>= 12 bytes, what
# ClassifyMdnsMessage needs). Only the QR bit — the high bit of the flags byte — is read: 0x0000
# flags is a query (QR=0), 0x8400 is a response (QR=1, AA). The reflector relays the bytes verbatim,
# so the receiver expects exactly what was sent.
MDNS_QUERY_HEX = "00000000000100000000000074657374"
MDNS_RESPONSE_HEX = "00008400000100010000000074657374"
# A query (QR=0) truncated to 8 bytes, below the 12-byte DNS header. ClassifyMdnsMessage rejects it
# on length before the QR bit is ever read, so it is dropped even when sent the query direction.
MDNS_SHORT_QUERY_HEX = "0000000000010000"

SSDP_GROUP_V4 = "239.255.255.250"
SSDP_GROUP_V6 = "ff02::c"
SSDP_PORT = 1900
# A non-SSDP UDP port: the reflector's filter keys on dest_port 1900, so a datagram to the group on
# this port is captured by the BPF but never dispatched to the reflector.
SSDP_WRONG_PORT = 1901
# SSDP discovery messages (HTTPU). The reflector classifies on the leading method token only and
# relays the bytes verbatim, so the receiver expects exactly what was sent; the HOST line's address
# is immaterial to the match.
SSDP_MSEARCH_HEX = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode().hex()
SSDP_NOTIFY_HEX = (
    "NOTIFY * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    "NT: upnp:rootdevice\r\n"
    "NTS: ssdp:alive\r\n\r\n"
).encode().hex()
# A unicast-style search response that strayed onto the group: neither M-SEARCH nor NOTIFY, so the
# reflector classifies it as non-SSDP and drops it.
SSDP_HTTP_RESPONSE_HEX = (
    "HTTP/1.1 200 OK\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode().hex()
# The unicast 200 OK a device sends back to an M-SEARCH; the round-trip responder replies with this
# and the searcher asserts it arrives verbatim after the reflector proxies it across segments.
SSDP_OK_HEX = (
    "HTTP/1.1 200 OK\r\n"
    "CACHE-CONTROL: max-age=1800\r\n"
    "ST: ssdp:all\r\n"
    "USN: uuid:device::ssdp:all\r\n"
    "LOCATION: http://device.invalid/desc.xml\r\n\r\n"
).encode().hex()
SEARCHER_SOURCE_PORT = 49152

# DIAL discovery: a DIAL-targeted M-SEARCH (ST is the DIAL service type). The emulator answers it with a
# 200 OK whose LOCATION points at its own target-side HTTP description endpoint.
DIAL_SERVICE_TYPE = "urn:dial-multiscreen-org:service:dial:1"
SSDP_DIAL_MSEARCH_HEX = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    f"ST: {DIAL_SERVICE_TYPE}\r\n\r\n"
).encode().hex()
DIAL_CLIENT_SOURCE_PORT = 49153


class CommandError(RuntimeError):
    def __init__(self, command: list[str], result: subprocess.CompletedProcess[str]) -> None:
        self.command = command
        self.result = result
        super().__init__(f"command failed with exit code {result.returncode}: {format_command(command)}")


IPV6_ALL_NODES = "ff02::1"


@dataclasses.dataclass(frozen=True)
class TestCase:
    name: str
    send_port: int
    receive_port: int
    expect_mac: str | None
    timeout_seconds: float
    send_mac: str | None = None
    send_payload_hex: str | None = None
    # IP version exercised end to end. The reflector runs both pipelines from one config;
    # each case drives just one of them.
    family: int = 4
    # Reflection direction. "forward" sends from the source network and receives on the target
    # (WoL, and mDNS queries); "reverse" swaps them (mDNS responses, target->source).
    direction: str = "forward"
    # Multicast group to send to and join on the receiver (mDNS). None keeps the WoL broadcast path.
    group: str | None = None
    # Exact payload the receiver must see, for protocols relayed verbatim (mDNS). None falls back to
    # the magic-packet / expect-none expectation.
    expect_payload_hex: str | None = None

    @property
    def send_address(self) -> str:
        if self.group is not None:
            return self.group
        return IPV6_ALL_NODES if self.family == 6 else "255.255.255.255"


TEST_CASES = [
    TestCase(
        name="reflects_matching_magic_packet",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=CONFIGURED_MAC,
        timeout_seconds=5.0,
        send_mac=CONFIGURED_MAC,
    ),
    TestCase(
        name="reflects_matching_magic_packet_ipv6",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=CONFIGURED_MAC,
        timeout_seconds=5.0,
        send_mac=CONFIGURED_MAC,
        family=6,
    ),
    TestCase(
        name="ignores_wrong_mac",
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_mac=WRONG_MAC,
    ),
    TestCase(
        name="ignores_unconfigured_port",
        send_port=UNCONFIGURED_PORT,
        receive_port=UNCONFIGURED_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_mac=CONFIGURED_MAC,
    ),
    TestCase(
        name="reflects_magic_packet_without_configured_mac",
        send_port=ANY_MAC_PORT,
        receive_port=ANY_MAC_PORT,
        expect_mac=WRONG_MAC,
        timeout_seconds=5.0,
        send_mac=WRONG_MAC,
    ),
    TestCase(
        name="ignores_malformed_packet_without_configured_mac",
        send_port=ANY_MAC_PORT,
        receive_port=ANY_MAC_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MALFORMED_MAGIC_PAYLOAD_HEX,
    ),
    # mDNS relays queries source->target and responses target->source. Reflected cases: the message
    # travels its allowed direction and arrives verbatim.
    TestCase(
        name="reflects_mdns_query",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_QUERY_HEX,
        expect_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
    ),
    TestCase(
        name="reflects_mdns_query_ipv6",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_QUERY_HEX,
        expect_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V6,
        family=6,
    ),
    TestCase(
        name="reflects_mdns_response",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_RESPONSE_HEX,
        expect_payload_hex=MDNS_RESPONSE_HEX,
        group=MDNS_GROUP_V4,
        direction="reverse",
    ),
    TestCase(
        name="reflects_mdns_response_ipv6",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=MDNS_RESPONSE_HEX,
        expect_payload_hex=MDNS_RESPONSE_HEX,
        group=MDNS_GROUP_V6,
        direction="reverse",
        family=6,
    ),
    # Dropped cases: a message travelling the wrong direction is not relayed. A query arriving on the
    # target (response direction) or a response arriving on the source (query direction) is ignored.
    TestCase(
        name="ignores_mdns_query_in_response_direction",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
        direction="reverse",
    ),
    TestCase(
        name="ignores_mdns_response_in_query_direction",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_RESPONSE_HEX,
        group=MDNS_GROUP_V4,
    ),
    TestCase(
        name="ignores_mdns_too_short_query",
        send_port=MDNS_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_SHORT_QUERY_HEX,
        group=MDNS_GROUP_V4,
    ),
    TestCase(
        name="ignores_mdns_wrong_port",
        send_port=MDNS_WRONG_PORT,
        receive_port=MDNS_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=MDNS_QUERY_HEX,
        group=MDNS_GROUP_V4,
    ),
    # SSDP relays M-SEARCH source->target and NOTIFY advertisements target->source. Reflected cases:
    # the message travels its allowed direction and arrives verbatim.
    TestCase(
        name="reflects_ssdp_msearch",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_MSEARCH_HEX,
        expect_payload_hex=SSDP_MSEARCH_HEX,
        group=SSDP_GROUP_V4,
    ),
    TestCase(
        name="reflects_ssdp_msearch_ipv6",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_MSEARCH_HEX,
        expect_payload_hex=SSDP_MSEARCH_HEX,
        group=SSDP_GROUP_V6,
        family=6,
    ),
    TestCase(
        name="reflects_ssdp_notify",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_NOTIFY_HEX,
        expect_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V4,
        direction="reverse",
    ),
    TestCase(
        name="reflects_ssdp_notify_ipv6",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=5.0,
        send_payload_hex=SSDP_NOTIFY_HEX,
        expect_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V6,
        direction="reverse",
        family=6,
    ),
    # Dropped cases: a message travelling the wrong direction, or one that is not an SSDP request, or
    # one to the wrong port, is not relayed.
    TestCase(
        name="ignores_ssdp_msearch_in_notify_direction",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_MSEARCH_HEX,
        group=SSDP_GROUP_V4,
        direction="reverse",
    ),
    TestCase(
        name="ignores_ssdp_notify_in_msearch_direction",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_NOTIFY_HEX,
        group=SSDP_GROUP_V4,
    ),
    TestCase(
        name="ignores_ssdp_http_response_on_group",
        send_port=SSDP_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_HTTP_RESPONSE_HEX,
        group=SSDP_GROUP_V4,
    ),
    TestCase(
        name="ignores_ssdp_wrong_port",
        send_port=SSDP_WRONG_PORT,
        receive_port=SSDP_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
        send_payload_hex=SSDP_MSEARCH_HEX,
        group=SSDP_GROUP_V4,
    ),
]


@dataclasses.dataclass(frozen=True)
class RoundTripCase:
    name: str
    family: int          # 4 or 6
    group: str
    timeout_seconds: float = 8.0
    # When False, no responder is started and the searcher must receive nothing — the reflector must
    # not fabricate or loop back a reply to an M-SEARCH no device answered.
    expect_reply: bool = True


ROUNDTRIP_CASES = [
    RoundTripCase(name="ssdp_msearch_roundtrip", family=4, group=SSDP_GROUP_V4),
    RoundTripCase(name="ssdp_msearch_roundtrip_ipv6", family=6, group=SSDP_GROUP_V6),
    RoundTripCase(name="ssdp_msearch_no_responder_no_reply", family=4, group=SSDP_GROUP_V4,
        timeout_seconds=2.0, expect_reply=False),
]

@dataclasses.dataclass(frozen=True)
class DialCase:
    name: str
    family: int          # 4 (DIAL is IPv4-only by spec; kept as a field for symmetry)
    group: str
    timeout_seconds: float = 8.0
    serve_seconds: float = 6.0
    passive: bool = False      # passive discovery (device advertises NOTIFY; client listens) vs active M-SEARCH
    unreachable: bool = False  # device advertises a dead HTTP port; the proxied fetch must fail, not hang


DIAL_CASES = [
    DialCase(name="dial_launch_roundtrip", family=4, group=SSDP_GROUP_V4),
    DialCase(name="dial_passive_notify_roundtrip", family=4, group=SSDP_GROUP_V4, passive=True),
    DialCase(name="dial_upstream_unreachable", family=4, group=SSDP_GROUP_V4, unreachable=True),
]

# Every selectable case, regardless of runner. Round trips are first-class: in the full suite and
# addressable by --case like any other. The runner is chosen per case by type (see make_runner).
ALL_CASES: list[TestCase | RoundTripCase | DialCase] = [*TEST_CASES, *ROUNDTRIP_CASES, *DIAL_CASES]


def format_command(command: list[str]) -> str:
    return " ".join(command)


def run_command(
    command: list[str],
    *,
    cwd: Path = REPO_ROOT,
    check: bool = True,
    capture: bool = True,
    echo: bool = True,
) -> subprocess.CompletedProcess[str]:
    if echo:
        print(f"+ {format_command(command)}", flush=True)
    stdout = subprocess.PIPE if capture else None
    stderr = subprocess.PIPE if capture else None
    result = subprocess.run(command, cwd=cwd, text=True, stdout=stdout, stderr=stderr, check=False)
    if check and result.returncode != 0:
        raise CommandError(command, result)
    return result


def docker(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    echo: bool = True,
) -> subprocess.CompletedProcess[str]:
    return run_command(["docker", *args], check=check, capture=capture, echo=echo)


def require_command(command: str) -> None:
    if shutil.which(command) is None:
        raise RuntimeError(f"required command not found: {command}")


def magic_packet_hex(mac: str) -> str:
    octets = bytes(int(part, 16) for part in mac.split(":"))
    return (b"\xff" * 6 + octets * 16).hex()


class DockerE2E:
    def __init__(self, args: argparse.Namespace, case: TestCase) -> None:
        self.args = args
        self.case = case
        self.prefix = f"reflector-e2e-{case.name.replace('_', '-')}-{uuid.uuid4().hex[:8]}"
        self.source_network = f"{self.prefix}-source"
        self.target_network = f"{self.prefix}-target"
        self.reflector_container = f"{self.prefix}-reflector"
        self.receiver_container = f"{self.prefix}-receiver"
        self.sender_container = f"{self.prefix}-sender"
        self.containers = [self.sender_container, self.receiver_container, self.reflector_container]
        self.networks = [self.source_network, self.target_network]
        self.config_path = E2E_DIR / "config.toml"

        # The sender lives on the network the traffic originates from and the receiver on the other;
        # "reverse" cases (mDNS responses) swap which is which. The receiver's interface is pinned so
        # the probe can join the multicast group on it.
        if case.direction == "reverse":
            self.sender_network, self.sender_ifname = self.target_network, REFLECTOR_TARGET_IFNAME
            self.receiver_network = self.source_network
        else:
            self.sender_network, self.sender_ifname = self.source_network, REFLECTOR_SOURCE_IFNAME
            self.receiver_network = self.target_network
        self.receiver_ifname = RECEIVER_IFNAME

    def __enter__(self) -> DockerE2E:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if exc_type is not None:
            self.print_diagnostics()

        if exc_type is not None and self.args.keep_on_failure:
            print(f"keeping Docker resources for failed case {self.case.name}: {self.prefix}", flush=True)
            return False

        self.cleanup()
        return False

    def cleanup(self) -> None:
        for container in self.containers:
            docker(["rm", "-f", container], check=False)
        for network in self.networks:
            docker(["network", "rm", network], check=False)

    def setup_networks(self) -> None:
        # Both networks are dual-stack: IPv4 cases are unaffected, and IPv6 cases need the
        # bridges to carry IPv6 so the reflector can listen on / emit to ff02::1.
        docker(["network", "create", "--driver", "bridge", "--ipv6", self.source_network])
        docker(["network", "create", "--driver", "bridge", "--ipv6", self.target_network])

    def start_reflector(self) -> None:
        # Pin in-container interface names per network. Without this, Docker's interface
        # naming at start time is non-deterministic when multiple endpoints are attached,
        # which made the reflector's SO_BINDTODEVICE land on the wrong bridge ~16% of runs.
        # Using a non-"eth" prefix avoids the prefix-collision caveat in moby/moby#49155.
        # Requires Docker 28.0+ (com.docker.network.endpoint.ifname driver-opt).
        docker(
            [
                "create",
                "--name",
                self.reflector_container,
                "--network",
                f"name={self.source_network},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_SOURCE_IFNAME}",
                "--network",
                f"name={self.target_network},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_TARGET_IFNAME}",
                "--cap-add",
                "NET_RAW",
                "--mount",
                f"type=bind,source={self.config_path},target=/etc/reflector/config.toml,readonly",
                self.args.image,
                "/etc/reflector/config.toml",
            ]
        )
        docker(["start", self.reflector_container])
        self.wait_for_reflector()

    def wait_for_container_log(self, container: str, marker: str, description: str) -> None:
        deadline = time.monotonic() + CONTAINER_READY_TIMEOUT_SECONDS
        last_state = "unknown"
        while time.monotonic() < deadline:
            logs = docker(["logs", container], check=False, echo=False)
            if marker in f"{logs.stdout}{logs.stderr}":
                return

            result = docker(
                ["inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", container],
                check=False,
                echo=False,
            )
            if result.returncode == 0:
                last_state = result.stdout.strip()
                if last_state.startswith("false "):
                    raise RuntimeError(f"{description} exited before becoming ready: {last_state}")

            time.sleep(0.1)

        raise RuntimeError(f"timed out waiting for {description} readiness marker ({marker}); last state: {last_state}")

    def wait_for_reflector(self) -> None:
        self.wait_for_container_log(self.reflector_container, REFLECTOR_READY_LOG, "reflector")

    def check_reflector_valgrind(self) -> None:
        # SIGTERM the reflector so it shuts down cleanly and valgrind runs its leak analysis, then read
        # its exit code: the image's --error-exitcode=1 fires on any leak, leaked fd, or memcheck error.
        docker(["stop", "-t", str(VALGRIND_STOP_GRACE_SECONDS), self.reflector_container])
        exit_code = docker(["wait", self.reflector_container]).stdout.strip()
        if exit_code != "0":
            print(f"\n--- valgrind report: {self.case.name} ---", file=sys.stderr, flush=True)
            report = docker(["logs", self.reflector_container], check=False)
            if report.stderr:
                print(report.stderr, end="", file=sys.stderr, flush=True)
            raise RuntimeError(f"valgrind reported errors in case {self.case.name} (reflector exited {exit_code})")

    def start_receiver(self) -> None:
        command = [
            "run",
            "-d",
            "--name",
            self.receiver_container,
            "--network",
            f"name={self.receiver_network},driver-opt=com.docker.network.endpoint.ifname={self.receiver_ifname}",
            "--mount",
            f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image,
            "python3",
            "/e2e/probe.py",
            "receive",
            "--port",
            str(self.case.receive_port),
            "--timeout",
            str(self.case.timeout_seconds),
        ]
        if self.case.expect_payload_hex is not None:
            command.extend(["--expect-payload-hex", self.case.expect_payload_hex])
        elif self.case.expect_mac is not None:
            command.extend(["--expect-mac", self.case.expect_mac])
        else:
            command.append("--expect-none")

        command.extend(["--family", str(self.case.family)])
        if self.case.group is not None:
            command.extend(["--join-group", self.case.group, "--interface", self.receiver_ifname])

        docker(command)
        self.wait_for_receiver()

    def wait_for_receiver(self) -> None:
        self.wait_for_container_log(self.receiver_container, RECEIVER_READY_LOG, "receiver")

    def run_sender(self) -> None:
        if self.case.send_payload_hex is not None:
            payload_args = ["--payload-hex", self.case.send_payload_hex]
        elif self.case.send_mac is not None:
            payload_args = ["--mac", self.case.send_mac]
        else:
            raise RuntimeError(f"case {self.case.name} has no send payload")

        docker(
            [
                "run",
                "--name",
                self.sender_container,
                # Pin the sender's interface name so the probe can scope multicast egress to it
                # deterministically (see start_reflector for the rationale).
                "--network",
                f"name={self.sender_network},driver-opt=com.docker.network.endpoint.ifname={self.sender_ifname}",
                "--mount",
                f"type=bind,source={E2E_DIR},target=/e2e,readonly",
                self.args.helper_image,
                "python3",
                "/e2e/probe.py",
                "send",
                *payload_args,
                "--port",
                str(self.case.send_port),
                "--address",
                self.case.send_address,
                "--interface",
                self.sender_ifname,
            ]
        )

    def wait_for_result(self) -> None:
        result = docker(["wait", self.receiver_container])
        exit_code = result.stdout.strip()
        logs = docker(["logs", self.receiver_container], check=False)
        if logs.stdout:
            print(logs.stdout, end="", flush=True)
        if logs.stderr:
            print(logs.stderr, end="", file=sys.stderr, flush=True)

        if exit_code != "0":
            raise RuntimeError(f"receiver failed with exit code {exit_code}")

    def print_reflector_logs(self) -> None:
        logs = docker(["logs", self.reflector_container], check=False)
        print(f"--- reflector logs: {self.case.name} ---", flush=True)
        if logs.stdout:
            print(logs.stdout, end="", flush=True)
        if logs.stderr:
            print(logs.stderr, end="", file=sys.stderr, flush=True)
        if not logs.stdout and not logs.stderr:
            print("<empty>", flush=True)

    def print_diagnostics(self) -> None:
        print(f"\n--- diagnostics for {self.case.name} ({self.prefix}) ---", file=sys.stderr, flush=True)
        for container in self.containers:
            inspect = docker(["inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", container], check=False)
            if inspect.returncode == 0:
                print(f"{container}: {inspect.stdout.strip()}", file=sys.stderr, flush=True)

            logs = docker(["logs", container], check=False)
            if logs.stdout or logs.stderr:
                print(f"--- logs: {container} ---", file=sys.stderr, flush=True)
                if logs.stdout:
                    print(logs.stdout, end="", file=sys.stderr, flush=True)
                if logs.stderr:
                    print(logs.stderr, end="", file=sys.stderr, flush=True)

        for network in self.networks:
            inspect = docker(["network", "inspect", network], check=False)
            if inspect.returncode == 0 and inspect.stdout:
                print(f"--- network: {network} ---", file=sys.stderr, flush=True)
                print(inspect.stdout, end="", file=sys.stderr, flush=True)

    def run(self) -> None:
        print(f"\n=== {self.case.name} ===", flush=True)
        self.setup_networks()
        self.start_reflector()
        self.start_receiver()
        self.run_sender()
        self.wait_for_result()
        print(f"PASS {self.case.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


class DockerRoundTrip(DockerE2E):
    def __init__(self, args: argparse.Namespace, case: RoundTripCase) -> None:
        # The base __init__ only reads case.name and case.direction; a TestCase shim reuses all its
        # network/reflector setup + cleanup with no duplication.
        shim = TestCase(name=case.name, send_port=SSDP_PORT, receive_port=SSDP_PORT,
            expect_mac=None, timeout_seconds=case.timeout_seconds, family=case.family,
            group=case.group, direction="forward")
        super().__init__(args, shim)
        self.rt = case
        self.responder_container = f"{self.prefix}-responder"
        self.searcher_container = f"{self.prefix}-searcher"
        self.containers = [self.searcher_container, self.responder_container, self.reflector_container]

    def start_responder(self) -> None:
        docker([
            "run", "-d", "--name", self.responder_container,
            "--network", f"name={self.target_network},driver-opt=com.docker.network.endpoint.ifname={RECEIVER_IFNAME}",
            "--mount", f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image, "python3", "/e2e/probe.py", "respond",
            "--port", str(SSDP_PORT), "--timeout", str(self.rt.timeout_seconds),
            "--family", str(self.rt.family), "--join-group", self.rt.group,
            "--interface", RECEIVER_IFNAME, "--reply-hex", SSDP_OK_HEX,
        ])
        self.wait_for_container_log(self.responder_container, "responder ready", "responder")

    def run_searcher(self) -> None:
        expectation = ["--expect-payload-hex", SSDP_OK_HEX] if self.rt.expect_reply else ["--expect-none"]
        docker([
            "run", "-d", "--name", self.searcher_container,
            "--network", f"name={self.source_network},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_SOURCE_IFNAME}",
            "--mount", f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image, "python3", "/e2e/probe.py", "search",
            "--source-port", str(SEARCHER_SOURCE_PORT), "--port", str(SSDP_PORT),
            "--address", self.rt.group, "--interface", REFLECTOR_SOURCE_IFNAME,
            "--family", str(self.rt.family), "--payload-hex", SSDP_MSEARCH_HEX,
            "--timeout", str(self.rt.timeout_seconds), *expectation,
        ])

    def wait_for_searcher(self) -> None:
        exit_code = docker(["wait", self.searcher_container]).stdout.strip()
        logs = docker(["logs", self.searcher_container], check=False)
        if logs.stdout:
            print(logs.stdout, end="", flush=True)
        if exit_code != "0":
            raise RuntimeError(f"searcher failed with exit code {exit_code}")

    def run(self) -> None:
        print(f"\n=== {self.rt.name} ===", flush=True)
        self.setup_networks()
        self.start_reflector()
        if self.rt.expect_reply:
            self.start_responder()   # must be listening before the search goes out
        self.run_searcher()
        self.wait_for_searcher()
        print(f"PASS {self.rt.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


class DockerDial(DockerE2E):
    def __init__(self, args: argparse.Namespace, case: DialCase) -> None:
        shim = TestCase(name=case.name, send_port=SSDP_PORT, receive_port=SSDP_PORT,
            expect_mac=None, timeout_seconds=case.timeout_seconds, family=case.family,
            group=case.group, direction="forward")
        super().__init__(args, shim)
        self.dial = case
        # The DIAL reflector loads a config with a single DIAL entry. The shared config's any-MAC
        # [discovery] entry also reflects SSDP, which would double-reflect the device's 200 OK (only one
        # copy rewritten) -- so the DIAL case gets its own config to keep the relayed reply unambiguous.
        self.config_path = E2E_DIR / "config-dial.toml"
        self.device_container = f"{self.prefix}-device"
        self.client_container = f"{self.prefix}-client"
        self.containers = [self.client_container, self.device_container, self.reflector_container]

    def container_ip(self, container: str, network: str) -> str:
        fmt = '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}'
        ip = docker(["inspect", "-f", fmt, container]).stdout.strip()
        if not ip:
            raise RuntimeError(f"no IPv4 address for {container} on {network}")
        return ip

    def start_device(self) -> None:
        # Single-homed on the target network: the device's HTTP endpoints are reachable only via the
        # reflector's egress-pinned upstream connect, so the peer it records is the reflector's target_if
        # address -- never the source-side client (which cannot route to the target subnet directly).
        cmd = [
            "run", "-d", "--name", self.device_container,
            "--network", f"name={self.target_network},driver-opt=com.docker.network.endpoint.ifname={RECEIVER_IFNAME}",
            "--mount", f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image, "python3", "/e2e/probe.py", "dial-device",
            "--port", str(SSDP_PORT), "--join-group", self.dial.group,
            "--interface", RECEIVER_IFNAME, "--family", str(self.dial.family),
            "--timeout", str(self.dial.timeout_seconds), "--serve-seconds", str(self.dial.serve_seconds),
        ]
        if self.dial.passive:
            cmd.append("--notify")
        if self.dial.unreachable:
            cmd.append("--unreachable")
        docker(cmd)
        self.wait_for_container_log(self.device_container, "dial-device ready", "dial-device")

    def run_client(self) -> None:
        # The client is single-homed on the source network. It is told the reflector's source_if address
        # (what the rewritten authorities must point at) and the device's true target_if address (which
        # must never leak through a rewrite). Both are read after the containers attached to their nets.
        device_target_ip = self.container_ip(self.device_container, self.target_network)
        refl_source_ip = self.container_ip(self.reflector_container, self.source_network)
        cmd = [
            "run", "-d", "--name", self.client_container,
            "--network", f"name={self.source_network},driver-opt=com.docker.network.endpoint.ifname={REFLECTOR_SOURCE_IFNAME}",
            "--mount", f"type=bind,source={E2E_DIR},target=/e2e,readonly",
            self.args.helper_image, "python3", "/e2e/probe.py", "dial-client",
            "--port", str(SSDP_PORT), "--address", self.dial.group, "--interface", REFLECTOR_SOURCE_IFNAME,
            "--family", str(self.dial.family), "--timeout", str(self.dial.timeout_seconds),
            "--reflector-authority", refl_source_ip, "--device-authority", device_target_ip,
        ]
        if self.dial.passive:
            cmd.append("--passive")  # listen for the relayed NOTIFY instead of sending an M-SEARCH
        else:
            cmd += ["--source-port", str(DIAL_CLIENT_SOURCE_PORT), "--payload-hex", SSDP_DIAL_MSEARCH_HEX]
        if self.dial.unreachable:
            cmd.append("--expect-fetch-failure")  # the device's upstream is dead; the fetch must fail
        docker(cmd)

    def wait_for_client(self) -> None:
        exit_code = docker(["wait", self.client_container]).stdout.strip()
        logs = docker(["logs", self.client_container], check=False)
        if logs.stdout:
            print(logs.stdout, end="", flush=True)
        if logs.stderr:
            print(logs.stderr, end="", file=sys.stderr, flush=True)
        if exit_code != "0":
            raise RuntimeError(f"dial-client failed with exit code {exit_code}")

    def assert_device_verdicts(self) -> None:
        # Two device-side checks: (1) the device exits non-zero if any request reached it with a Host that
        # was not rewritten to its own authority (the reflector must rewrite Host source->device); (2) the
        # reflector's upstream connect is egress-pinned to target_if, so the only peer the device recorded
        # must be exactly the reflector's target_if address.
        refl_target_ip = self.container_ip(self.reflector_container, self.target_network)
        exit_code = docker(["wait", self.device_container]).stdout.strip()
        logs = docker(["logs", self.device_container], check=False)
        if logs.stdout:
            print(logs.stdout, end="", flush=True)
        if logs.stderr:
            print(logs.stderr, end="", file=sys.stderr, flush=True)
        if exit_code != "0":
            raise RuntimeError(f"dial-device failed with exit code {exit_code} "
                               f"(a request reached it with an unrewritten Host)")
        marker = "dial-device upstream peers seen: "
        line = next((ln for ln in logs.stdout.splitlines() if marker in ln), None)
        if line is None:
            raise RuntimeError("dial-device did not report the upstream peers it saw")
        seen = ast.literal_eval(line.split(marker, 1)[1].strip())
        if seen != [refl_target_ip]:
            raise RuntimeError(f"device saw upstream peers {seen}, expected only the reflector's target_if "
                               f"address [{refl_target_ip!r}] (egress not pinned to target_if)")
        print(f"dial: every request's Host was rewritten to the device, and every upstream connection came "
              f"from the reflector's target_if address {refl_target_ip}", flush=True)

    def run(self) -> None:
        print(f"\n=== {self.dial.name} ===", flush=True)
        self.setup_networks()
        self.start_reflector()
        self.start_device()      # must be serving before the client searches
        self.run_client()
        self.wait_for_client()        # client-side verdict: rewrites (or, for unreachable, the expected fail)
        if self.dial.unreachable:
            docker(["wait", self.device_container])  # no HTTP server in this mode: nothing to assert
            logs = docker(["logs", self.device_container], check=False)
            if logs.stdout:
                print(logs.stdout, end="", flush=True)
        else:
            self.assert_device_verdicts()  # device-side verdict: Host rewrite + egress-pinned upstream
        print(f"PASS {self.dial.name}", flush=True)
        if self.args.show_reflector_logs:
            time.sleep(0.5)
            self.print_reflector_logs()


def make_runner(args: argparse.Namespace, case: TestCase | RoundTripCase | DialCase) -> DockerE2E:
    if isinstance(case, DialCase):
        return DockerDial(args, case)
    if isinstance(case, RoundTripCase):
        return DockerRoundTrip(args, case)
    return DockerE2E(args, case)


def build_reflector_image(image: str, target: str | None = None) -> None:
    command = ["build", "-t", image]
    if target is not None:
        command += ["--target", target]
    docker([*command, "."], capture=False)


def select_cases(case_names: list[str]) -> list[TestCase | RoundTripCase | DialCase]:
    if not case_names:
        return ALL_CASES

    cases_by_name = {case.name: case for case in ALL_CASES}
    unknown = sorted(set(case_names) - set(cases_by_name))
    if unknown:
        available = ", ".join(sorted(cases_by_name))
        raise RuntimeError(f"unknown e2e case(s): {', '.join(unknown)}. Available cases: {available}")

    return [cases_by_name[name] for name in case_names]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Docker-backed reflector e2e tests")
    parser.add_argument("--image", default=None,
        help="reflector image tag to run (default: reflector:e2e, or reflector:e2e-valgrind with --valgrind)")
    parser.add_argument("--skip-build", action="store_true", help="use --image without building it first")
    parser.add_argument("--valgrind", action="store_true",
        help="run the reflector under Valgrind memcheck; fail the run on any leak, leaked fd, or memcheck error")
    parser.add_argument("--helper-image", default=DEFAULT_HELPER_IMAGE, help="Python image used for UDP probes")
    parser.add_argument("--keep-on-failure", action="store_true", help="leave Docker resources behind after a failure")
    parser.add_argument("--show-reflector-logs", action="store_true", help="print reflector container logs after each passing case")
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        choices=[case.name for case in ALL_CASES],
        help="e2e case to run; may be passed more than once",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    require_command("docker")
    if args.image is None:
        args.image = VALGRIND_REFLECTOR_IMAGE if args.valgrind else DEFAULT_REFLECTOR_IMAGE

    cases = select_cases(args.case)
    print(f"expected magic payload: {magic_packet_hex(CONFIGURED_MAC)}", flush=True)

    if not args.skip_build:
        build_reflector_image(args.image, "runtime-valgrind" if args.valgrind else None)

    for case in cases:
        with make_runner(args, case) as runner:
            runner.run()
            if args.valgrind:
                runner.check_reflector_valgrind()

    suffix = " under valgrind" if args.valgrind else ""
    print(f"\nPASS {len(cases)} e2e case(s){suffix}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CommandError as exc:
        print(str(exc), file=sys.stderr)
        if exc.result.stdout:
            print(exc.result.stdout, end="", file=sys.stderr)
        if exc.result.stderr:
            print(exc.result.stderr, end="", file=sys.stderr)
        raise SystemExit(1)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
