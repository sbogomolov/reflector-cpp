#!/usr/bin/env python3

from __future__ import annotations

import argparse
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
DEFAULT_HELPER_IMAGE = "python:3.13-alpine"
CONFIGURED_MAC = "02:42:ac:11:00:09"
WRONG_MAC = "02:42:ac:11:00:0a"
CONFIGURED_PORT = 40009
UNCONFIGURED_PORT = 40010
REFLECTOR_READY_LOG = "Starting dispatcher event loop"
RECEIVER_READY_LOG = "receiver ready: UDP socket bound"
PROBE_INTERFACE = "eth0"


class CommandError(RuntimeError):
    def __init__(self, command: list[str], result: subprocess.CompletedProcess[str]) -> None:
        self.command = command
        self.result = result
        super().__init__(f"command failed with exit code {result.returncode}: {format_command(command)}")


@dataclasses.dataclass(frozen=True)
class TestCase:
    name: str
    send_mac: str
    send_port: int
    receive_port: int
    expect_mac: str | None
    timeout_seconds: float


TEST_CASES = [
    TestCase(
        name="reflects_matching_magic_packet",
        send_mac=CONFIGURED_MAC,
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=CONFIGURED_MAC,
        timeout_seconds=5.0,
    ),
    TestCase(
        name="ignores_wrong_mac",
        send_mac=WRONG_MAC,
        send_port=CONFIGURED_PORT,
        receive_port=CONFIGURED_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
    ),
    TestCase(
        name="ignores_unconfigured_port",
        send_mac=CONFIGURED_MAC,
        send_port=UNCONFIGURED_PORT,
        receive_port=UNCONFIGURED_PORT,
        expect_mac=None,
        timeout_seconds=1.5,
    ),
]


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
        docker(["network", "create", "--driver", "bridge", self.source_network])
        docker(["network", "create", "--driver", "bridge", self.target_network])

    def start_reflector(self) -> None:
        docker(
            [
                "create",
                "--name",
                self.reflector_container,
                "--network",
                self.source_network,
                "--cap-add",
                "NET_RAW",
                "--mount",
                f"type=bind,source={self.config_path},target=/etc/reflector/config.toml,readonly",
                self.args.image,
                "/etc/reflector/config.toml",
            ]
        )
        docker(["network", "connect", self.target_network, self.reflector_container])
        docker(["start", self.reflector_container])
        self.wait_for_reflector()

    def wait_for_container_log(self, container: str, marker: str, description: str) -> None:
        deadline = time.monotonic() + 5.0
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

    def start_receiver(self) -> None:
        command = [
            "run",
            "-d",
            "--name",
            self.receiver_container,
            "--network",
            self.target_network,
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
            "--interface",
            PROBE_INTERFACE,
        ]
        if self.case.expect_mac is None:
            command.append("--expect-none")
        else:
            command.extend(["--expect-mac", self.case.expect_mac])

        docker(command)
        self.wait_for_receiver()

    def wait_for_receiver(self) -> None:
        self.wait_for_container_log(self.receiver_container, RECEIVER_READY_LOG, "receiver")

    def run_sender(self) -> None:
        # TODO: Investigate intermittent Docker bridge delivery misses for 255.255.255.255.
        docker(
            [
                "run",
                "--name",
                self.sender_container,
                "--network",
                self.source_network,
                "--mount",
                f"type=bind,source={E2E_DIR},target=/e2e,readonly",
                self.args.helper_image,
                "python3",
                "/e2e/probe.py",
                "send",
                "--mac",
                self.case.send_mac,
                "--port",
                str(self.case.send_port),
                "--interface",
                PROBE_INTERFACE,
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
        for container in [self.reflector_container, self.receiver_container, self.sender_container]:
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


def build_reflector_image(image: str) -> None:
    docker(["build", "-t", image, "."], capture=False)


def select_cases(case_names: list[str]) -> list[TestCase]:
    if not case_names:
        return TEST_CASES

    cases_by_name = {case.name: case for case in TEST_CASES}
    unknown = sorted(set(case_names) - set(cases_by_name))
    if unknown:
        available = ", ".join(sorted(cases_by_name))
        raise RuntimeError(f"unknown e2e case(s): {', '.join(unknown)}. Available cases: {available}")

    return [cases_by_name[name] for name in case_names]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Docker-backed reflector e2e tests")
    parser.add_argument("--image", default=DEFAULT_REFLECTOR_IMAGE, help="reflector image tag to run")
    parser.add_argument("--skip-build", action="store_true", help="use --image without building it first")
    parser.add_argument("--helper-image", default=DEFAULT_HELPER_IMAGE, help="Python image used for UDP probes")
    parser.add_argument("--keep-on-failure", action="store_true", help="leave Docker resources behind after a failure")
    parser.add_argument("--show-reflector-logs", action="store_true", help="print reflector container logs after each passing case")
    parser.add_argument(
        "--case",
        action="append",
        default=[],
        choices=[case.name for case in TEST_CASES],
        help="e2e case to run; may be passed more than once",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    require_command("docker")

    cases = select_cases(args.case)
    print(f"expected magic payload: {magic_packet_hex(CONFIGURED_MAC)}", flush=True)

    if not args.skip_build:
        build_reflector_image(args.image)

    for case in cases:
        with DockerE2E(args, case) as runner:
            runner.run()

    print(f"\nPASS {len(cases)} e2e case(s)", flush=True)
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
