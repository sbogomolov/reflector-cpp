#!/usr/bin/env python3
"""Leak-check the reflector under a sustained mDNS/SSDP flood with valgrind.

Builds the no-sanitizer valgrind image (e2e/valgrind/Dockerfile), runs the reflector under valgrind
on a two-network topology (matching the e2e setup), floods it from the source side for a while, then
sends SIGTERM so the daemon exits cleanly and valgrind reports leaks + leaked fds at exit.

  python3 e2e/valgrind/soak.py [--duration 90] [--skip-build]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import uuid
from pathlib import Path

VDIR = Path(__file__).resolve().parent
E2E = VDIR.parent
REPO = E2E.parent

IMAGE = "reflector:valgrind"
HELPER = "python:3.13-alpine"
CONFIG = E2E / "config.toml"

SRC_IFNAME = "wol_src"
DST_IFNAME = "wol_dst"
REFLECTOR_READY = "Starting dispatcher event loop"
READY_TIMEOUT = 90.0   # valgrind start-up is slow
STOP_GRACE = 60        # seconds for valgrind to finish leak analysis after SIGTERM


def docker(args: list[str], *, check: bool = True, echo: bool = True) -> subprocess.CompletedProcess[str]:
    if echo:
        print("+ docker " + " ".join(args), flush=True)
    return subprocess.run(["docker", *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def wait_for_log(container: str, marker: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = docker(["logs", container], check=False, echo=False)
        if marker in f"{logs.stdout}{logs.stderr}":
            return
        state = docker(["inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", container], check=False, echo=False)
        if state.stdout.strip().startswith("false "):
            raise RuntimeError(f"{container} exited before ready: {state.stdout.strip()}\n"
                               f"{logs.stdout}\n{logs.stderr}")
        time.sleep(0.3)
    raise RuntimeError(f"timed out waiting for '{marker}' in {container}")


def sample_vmrss_kb(container: str) -> int | None:
    # PID 1 is valgrind here; its VmRSS is inflated by valgrind's shadow memory, but if the app
    # accumulated heap the figure would still climb — so the TREND (plateau vs rise) is what matters.
    r = docker(["exec", container, "grep", "VmRSS", "/proc/1/status"], check=False, echo=False)
    parts = r.stdout.split()
    return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None


def main() -> int:
    ap = argparse.ArgumentParser(description="valgrind memory-leak soak for the reflector")
    ap.add_argument("--duration", type=float, default=90.0, help="seconds to flood")
    ap.add_argument("--interval", type=float, default=0.05, help="seconds between flood iterations")
    ap.add_argument("--sample-interval", type=float, default=4.0, help="seconds between VmRSS samples")
    ap.add_argument("--skip-build", action="store_true", help="reuse an existing reflector:valgrind image")
    args = ap.parse_args()

    if not args.skip_build:
        print("=== building valgrind image (no-sanitizer -g build) ===", flush=True)
        subprocess.run(["docker", "build", "-f", str(VDIR / "Dockerfile"), "-t", IMAGE, str(REPO)], check=True)

    prefix = f"reflector-valgrind-{uuid.uuid4().hex[:8]}"
    src_net, dst_net = f"{prefix}-src", f"{prefix}-dst"
    reflector, sender = f"{prefix}-reflector", f"{prefix}-sender"
    networks = [src_net, dst_net]
    containers = [sender, reflector]

    try:
        docker(["network", "create", "--driver", "bridge", src_net])
        docker(["network", "create", "--driver", "bridge", dst_net])

        docker([
            "create", "--name", reflector,
            "--network", f"name={src_net},driver-opt=com.docker.network.endpoint.ifname={SRC_IFNAME}",
            "--network", f"name={dst_net},driver-opt=com.docker.network.endpoint.ifname={DST_IFNAME}",
            "--cap-add", "NET_RAW",
            "--mount", f"type=bind,source={CONFIG},target=/etc/reflector/config.toml,readonly",
            IMAGE, "/etc/reflector/config.toml",
        ])
        docker(["start", reflector])
        print("=== waiting for reflector (under valgrind) to come up ===", flush=True)
        wait_for_log(reflector, REFLECTOR_READY, READY_TIMEOUT)

        print(f"=== flooding for {args.duration}s, sampling VmRSS under valgrind ===", flush=True)
        docker([
            "run", "-d", "--name", sender,
            "--network", f"name={src_net},driver-opt=com.docker.network.endpoint.ifname={SRC_IFNAME}",
            "--mount", f"type=bind,source={VDIR},target=/flood,readonly",
            HELPER, "python3", "/flood/flood.py",
            "--interface", SRC_IFNAME, "--duration", str(args.duration), "--interval", str(args.interval),
        ])
        print(f"\n{'t(s)':>6} {'VmRSS(kB)':>12}   (valgrind-inflated absolute; watch the TREND)", flush=True)
        samples: list[int] = []
        start = time.monotonic()
        while time.monotonic() - start < args.duration:
            t = time.monotonic() - start
            rss = sample_vmrss_kb(reflector)
            if rss is not None:
                samples.append(rss)
                print(f"{t:6.0f} {rss:12d}", flush=True)
            time.sleep(args.sample_interval)
        docker(["wait", sender], check=False)
        if samples:
            print(f"VmRSS under valgrind: first={samples[0]} peak={max(samples)} last={samples[-1]} kB "
                  f"(last-first={samples[-1] - samples[0]:+d} kB)", flush=True)

        print(f"=== SIGTERM reflector; giving valgrind up to {STOP_GRACE}s to report ===", flush=True)
        docker(["stop", "-t", str(STOP_GRACE), reflector])

        logs = docker(["logs", reflector], check=False, echo=False)
        report = f"{logs.stdout}\n{logs.stderr}"
        print("\n================= VALGRIND REPORT =================", flush=True)
        interesting = [
            ln for ln in report.splitlines()
            if any(k in ln for k in (
                "definitely lost", "indirectly lost", "possibly lost", "still reachable",
                "LEAK SUMMARY", "HEAP SUMMARY", "ERROR SUMMARY", "FILE DESCRIPTORS",
                "Open file descriptor", "in use at exit", "total heap usage", "blocks are",
            ))
        ]
        print("\n".join(interesting) if interesting else "(no valgrind summary found — see full logs)", flush=True)

        # Surface the tail of the reflector's own debug logs so the session/timer lifecycle is visible.
        print("\n=========== reflector debug log (tail) ===========", flush=True)
        tail = [ln for ln in logs.stdout.splitlines() if "session" in ln.lower() or "timer" in ln.lower()]
        print("\n".join(tail[-25:]) if tail else "(no session/timer logs)", flush=True)
        return 0
    finally:
        for c in containers:
            docker(["rm", "-f", c], check=False, echo=False)
        for n in networks:
            docker(["network", "rm", n], check=False, echo=False)


if __name__ == "__main__":
    raise SystemExit(main())
