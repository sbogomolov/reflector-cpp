#!/usr/bin/env python3
"""Heap-bytes-in-use OVER TIME under a sustained flood, via valgrind massif.

memcheck's "0 at exit" can't see in-flight growth, and a process's VmRSS under valgrind is confounded
by valgrind's own overhead. massif profiles the APP's heap (malloc bytes in use) at many points during
the run, excluding valgrind's bookkeeping — so its timeline is the clean answer to "does our heap grow
or plateau?". Prints ms_print's ASCII heap-over-time graph + peak snapshot.

  python3 e2e/valgrind/soak_massif.py [--duration 90]
"""

from __future__ import annotations

import argparse
import subprocess
import time
import uuid
from pathlib import Path

VDIR = Path(__file__).resolve().parent
E2E = VDIR.parent
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


def main() -> int:
    ap = argparse.ArgumentParser(description="massif heap-over-time soak")
    ap.add_argument("--duration", type=float, default=90.0)
    ap.add_argument("--interval", type=float, default=0.05)
    args = ap.parse_args()

    prefix = f"reflector-massif-{uuid.uuid4().hex[:8]}"
    src_net, dst_net = f"{prefix}-src", f"{prefix}-dst"
    reflector, sender = f"{prefix}-reflector", f"{prefix}-sender"
    out = "/tmp/massif.out"
    try:
        docker(["network", "create", "--driver", "bridge", src_net], echo=True)
        docker(["network", "create", "--driver", "bridge", dst_net], echo=True)
        docker([
            "run", "-d", "--name", reflector, "--entrypoint", "valgrind",
            "--network", f"name={src_net},driver-opt=com.docker.network.endpoint.ifname={SRC_IFNAME}",
            "--network", f"name={dst_net},driver-opt=com.docker.network.endpoint.ifname={DST_IFNAME}",
            "--cap-add", "NET_RAW",
            "--mount", f"type=bind,source={CONFIG},target=/etc/reflector/config.toml,readonly",
            IMAGE, "--tool=massif", "--time-unit=ms", f"--massif-out-file={out}",
            "--detailed-freq=1", "/usr/local/bin/reflector", "/etc/reflector/config.toml",
        ], echo=True)
        wait_for_log(reflector, REFLECTOR_READY, 60.0)

        print(f"=== flooding for {args.duration}s under massif ===", flush=True)
        docker([
            "run", "-d", "--name", sender,
            "--network", f"name={src_net},driver-opt=com.docker.network.endpoint.ifname={SRC_IFNAME}",
            "--mount", f"type=bind,source={VDIR},target=/flood,readonly",
            HELPER, "python3", "/flood/flood.py", "--interface", SRC_IFNAME,
            "--duration", str(args.duration), "--interval", str(args.interval),
        ], echo=True)
        docker(["wait", sender], check=False)

        # massif writes its out file only at (clean) exit -> SIGTERM, then copy it out of the stopped
        # container and ms_print it in a throwaway container (the image carries ms_print).
        docker(["stop", "-t", "40", reflector])
        host_out = VDIR / "massif.out"
        docker(["cp", f"{reflector}:{out}", str(host_out)])
        report = docker(["run", "--rm", "--entrypoint", "ms_print",
            "--mount", f"type=bind,source={VDIR},target=/m,readonly", IMAGE, "/m/massif.out"], check=False)
        print("\n================= MASSIF HEAP-OVER-TIME =================", flush=True)
        print(report.stdout or report.stderr, flush=True)
        host_out.unlink(missing_ok=True)
        return 0
    finally:
        for c in (sender, reflector):
            docker(["rm", "-f", c], check=False)
        for n in (src_net, dst_net):
            docker(["network", "rm", n], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
