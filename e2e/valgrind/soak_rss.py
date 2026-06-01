#!/usr/bin/env python3
"""Watch the reflector's memory OVER TIME under a sustained mDNS/SSDP flood.

valgrind --leak-check only reports what survives to exit; it cannot see in-flight growth (a daemon
that accumulates for hours and frees only in destructors shows "0 at exit" yet climbs the whole
time). This samples the live process instead:

  - VmRSS / VmHWM from /proc/1/status   -> the process resident set (our pages; excludes kernel bufs)
  - the cgroup memory figure (docker stats) -> total incl. kernel socket buffers (what WinBox shows)

every interval during the flood, so we can see whether memory is FLAT (bounded) or CLIMBING (growth).
Runs the binary natively (NOT under valgrind, whose own RSS would dominate). Reuses the reflector:valgrind
image only because it is debian-based (has /proc + coreutils) and carries the no-sanitizer binary.

  python3 e2e/valgrind/soak_rss.py [--duration 120] [--interval 2]
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


def docker(args: list[str], *, check: bool = True, echo: bool = False) -> subprocess.CompletedProcess[str]:
    if echo:
        print("+ docker " + " ".join(args), flush=True)
    return subprocess.run(["docker", *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=check)


def wait_for_log(container: str, marker: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = docker(["logs", container], check=False)
        if marker in f"{logs.stdout}{logs.stderr}":
            return
        state = docker(["inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", container], check=False)
        if state.stdout.strip().startswith("false "):
            raise RuntimeError(f"{container} exited before ready: {state.stdout.strip()}\n{logs.stdout}\n{logs.stderr}")
        time.sleep(0.3)
    raise RuntimeError(f"timed out waiting for '{marker}' in {container}")


def sample_vmrss_kb(container: str) -> int | None:
    r = docker(["exec", container, "grep", "VmRSS", "/proc/1/status"], check=False)
    # "VmRSS:    1234 kB"
    parts = r.stdout.split()
    return int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None


def sample_cgroup(container: str) -> str:
    r = docker(["stats", "--no-stream", "--format", "{{.MemUsage}}", container], check=False)
    return r.stdout.strip().split("/")[0].strip() or "?"


def main() -> int:
    ap = argparse.ArgumentParser(description="RSS-over-time soak for the reflector")
    ap.add_argument("--duration", type=float, default=120.0, help="seconds to flood")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between samples")
    ap.add_argument("--flood-interval", type=float, default=0.04, help="seconds between flood iterations")
    args = ap.parse_args()

    prefix = f"reflector-rss-{uuid.uuid4().hex[:8]}"
    src_net, dst_net = f"{prefix}-src", f"{prefix}-dst"
    reflector, sender = f"{prefix}-reflector", f"{prefix}-sender"
    try:
        docker(["network", "create", "--driver", "bridge", src_net], echo=True)
        docker(["network", "create", "--driver", "bridge", dst_net], echo=True)

        # Native run (no valgrind): override the image's valgrind ENTRYPOINT with the bare binary.
        docker([
            "run", "-d", "--name", reflector, "--entrypoint", "/usr/local/bin/reflector",
            "--network", f"name={src_net},driver-opt=com.docker.network.endpoint.ifname={SRC_IFNAME}",
            "--network", f"name={dst_net},driver-opt=com.docker.network.endpoint.ifname={DST_IFNAME}",
            "--cap-add", "NET_RAW",
            "--mount", f"type=bind,source={CONFIG},target=/etc/reflector/config.toml,readonly",
            IMAGE, "/etc/reflector/config.toml",
        ], echo=True)
        wait_for_log(reflector, REFLECTOR_READY, 30.0)

        baseline = sample_vmrss_kb(reflector)
        print(f"baseline VmRSS={baseline} kB cgroup={sample_cgroup(reflector)}", flush=True)

        docker([
            "run", "-d", "--name", sender,
            "--network", f"name={src_net},driver-opt=com.docker.network.endpoint.ifname={SRC_IFNAME}",
            "--mount", f"type=bind,source={VDIR},target=/flood,readonly",
            HELPER, "python3", "/flood/flood.py", "--interface", SRC_IFNAME,
            "--duration", str(args.duration), "--interval", str(args.flood_interval),
        ], echo=True)

        print(f"\n{'t(s)':>6} {'VmRSS(kB)':>10} {'Δbaseline':>10}  cgroup", flush=True)
        samples = []
        start = time.monotonic()
        end = start + args.duration
        while time.monotonic() < end:
            t = time.monotonic() - start
            rss = sample_vmrss_kb(reflector)
            cg = sample_cgroup(reflector)
            if rss is not None:
                samples.append((t, rss))
                delta = rss - baseline if baseline else 0
                print(f"{t:6.0f} {rss:10d} {delta:+10d}  {cg}", flush=True)
            time.sleep(args.interval)

        docker(["wait", sender], check=False)
        flog = docker(["logs", sender], check=False)
        print(flog.stdout.strip().splitlines()[-1] if flog.stdout.strip() else "(no flood output)", flush=True)

        if samples:
            rss_vals = [r for _, r in samples]
            first, peak, last = rss_vals[0], max(rss_vals), rss_vals[-1]
            print(f"\nVmRSS: baseline={baseline} first={first} peak={peak} last={last} kB "
                  f"(peak-baseline={peak - (baseline or 0):+d} kB, last-first={last - first:+d} kB)", flush=True)
            print(f"final cgroup={sample_cgroup(reflector)}", flush=True)
        return 0
    finally:
        for c in (sender, reflector):
            docker(["rm", "-f", c], check=False)
        for n in (src_net, dst_net):
            docker(["network", "rm", n], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
