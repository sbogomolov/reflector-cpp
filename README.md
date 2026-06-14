# reflector

Reflects link-local service traffic between two network interfaces. Useful when the devices that
talk to each other live on different L2 segments that don't forward each other's broadcasts or
multicasts — for example, a router bridging a wired LAN to a Wi-Fi network. Three protocols are
supported today:

- **Wake-on-LAN** — magic packets sent on one interface are re-emitted on another, so a sender can
  wake a host on a different segment.
- **multicast DNS (mDNS)** — service discovery traffic is relayed between two interfaces, so clients
  on one segment can discover responders on the other.
- **SSDP (UPnP/DLNA)** — discovery traffic is relayed between two interfaces, so a caster on one
  segment can find renderers (TVs, media servers) on the other.

By default, each reflector entry requires IPv4 handling and attempts IPv6 on a best-effort basis. If
IPv4 cannot be initialized for an entry, startup fails; if only IPv6 cannot be initialized, IPv4
keeps running. The per-protocol re-emit details are described under [Configuration](#configuration).

## Platform support

Linux and macOS. The CI workflow runs the unit suite on Ubuntu 24.04 x64, Ubuntu 24.04 arm64, and macOS 15, plus cross-compiled 32-bit ARM builds (`linux/arm/v7` and `linux/arm/v5`) whose unit suites run under QEMU; it also runs Docker build and e2e jobs on Ubuntu 24.04.

The published multi-arch Docker image targets `linux/amd64`, `linux/arm64`, `linux/arm/v7`, and `linux/arm/v5`. The 32-bit ARM variants let it run on MikroTik routers through the RouterOS *Container* feature: `arm/v7` for older ARMv7 devices (e.g. RB3011, RB4011, hAP ac2/ac3, CRS3xx), and `arm/v5` for the newer low-end ARMv5 boxes built on the EN7562CT SoC (hEX refresh, hEX S refresh, hAP ax S).

## Build

Prerequisites:

- CMake ≥ 3.28, Ninja, Git
- A C++23 toolchain. The standard library bits used here (`std::println`, `std::expected`, `std::format`) require:
  - GCC ≥ 14, or
  - Clang ≥ 18 (with libc++ or libstdc++ from GCC 14+), or
  - AppleClang ≥ 16 (Xcode 16)

CMake will fail at configure time with a clear message if the toolchain is too old.

```sh
./cmake_gen.sh           # configures build/ in Debug mode (with ASan+UBSan) using Ninja
./cmake_gen.sh Release   # configures build/ in Release mode using Ninja
cmake --build build      # produces build/reflector and build/tests/reflector_test
```

Debug builds enable AddressSanitizer + UndefinedBehaviorSanitizer by default. Pass `-DREFLECTOR_SANITIZE=OFF` to opt out.
Release builds use `-O3` and enable IPO/LTO when the toolchain supports it.

If `ccache` is installed, CMake uses it automatically as the C++ compiler launcher. Disable this with `-DREFLECTOR_ENABLE_CCACHE=OFF`, or set `CMAKE_CXX_COMPILER_LAUNCHER` explicitly to use another launcher.

C++ dependencies (`tomlplusplus`, `googletest`) are fetched via `FetchContent`, so no distro packages are needed for those libraries.

### Docker build

Requires Docker with Buildx.

```sh
./docker_build.sh
./docker_build.sh --push
```

The runtime image uses pinned Debian/distroless base image digests. By default, `./docker_build.sh` loads a single-platform image into the local Docker engine and tags it as `reflector:<version>` and `reflector:latest`. With `--push`, it publishes `ghcr.io/sbogomolov/reflector` as a multi-platform manifest for `linux/amd64`, `linux/arm64`, `linux/arm/v7`, and `linux/arm/v5`; override the destination with `--image`, or override architectures with `--platforms` for unusual deployment targets.

## Release

The project version in `CMakeLists.txt` is the single source of truth: `version.sh` extracts it, and
`docker_build.sh` (image tag), `release.sh` (git tag), and the GitHub release name all derive from
it. To cut a release:

- Bump the project version in `CMakeLists.txt` and merge it to `origin/main`.
- From a clean `main` in sync with `origin/main`, run `./release.sh`.

`./release.sh` automates the rest: it verifies CI is green on the release commit, prints the detected
version and asks for confirmation, tags `v<version>` and pushes it, creates the GitHub release (with
generated notes), and publishes the Docker images with `./docker_build.sh --push`. The pushed tag is
independently re-checked against `CMakeLists.txt` by the `Tag version check` workflow. Requires the
GitHub CLI (`gh`, authenticated) and Docker.

## Run

```sh
./build/reflector [config.toml]
```

The default config path is `./config.toml`. The process logs to stdout and shuts down cleanly on `SIGINT` / `SIGTERM`.

### Runtime privileges

The reflector opens an L2 packet-capture socket on each interface it listens on to observe incoming
packets, and a UDP sender bound to each interface it emits on to re-emit them. The capture socket is
what drives the privilege requirements below; the sender does not need to bind to a port (it sends
only), so no port-related privileges are required. mDNS and SSDP additionally join their multicast group(s) on the
capture socket, which needs no privilege beyond what opening that socket already requires.

#### Linux

Capture uses `AF_PACKET`; the sender uses `SO_BINDTODEVICE`. Both require `CAP_NET_RAW`.
Either run as root or grant the capability once:

```sh
sudo setcap cap_net_raw=eip ./build/reflector
```

#### macOS

Capture uses BPF (`/dev/bpf*`); the sender uses `IP_BOUND_IF` / `IPV6_BOUND_IF`, which
need no extra privileges. BPF devices are owned by `root:wheel` with mode `0600` on a
default install, so out of the box the reflector must run as root. To run unprivileged,
install Wireshark's `ChmodBPF` helper — it creates an `access_bpf` group, adds the
current user to it, and re-applies the right permissions to `/dev/bpf*` on every boot:

```sh
open "/Applications/Wireshark.app/Contents/Resources/Extras/Install ChmodBPF.pkg"
```

Log out and back in after installing for the group membership to take effect.

### Run in Docker

Prebuilt multi-arch images are published to `ghcr.io/sbogomolov/reflector`, tagged `latest` and per release version, for `linux/amd64`, `linux/arm64`, `linux/arm/v7`, and `linux/arm/v5`; Docker pulls the variant matching the host. The image is a single static binary on `scratch` — no shell, no package manager. Its entrypoint is the reflector, with `/etc/reflector/config.toml` as the default argument, so mount your config there.

Because the reflector captures at L2 on each interface, the container must be **on the real segments it bridges**, not on a default NAT bridge network (which would hide that traffic from it). On a Linux host, `--network host` is the simplest way:

```sh
docker run --rm \
    --network host \
    -v /path/to/config.toml:/etc/reflector/config.toml:ro \
    ghcr.io/sbogomolov/reflector:latest
```

`CAP_NET_RAW` is required (see [Runtime privileges](#runtime-privileges)) and is in Docker's default capability set, so the command above works as-is. For least privilege, drop everything else and grant just that one:

```sh
docker run --rm \
    --network host \
    --cap-drop ALL --cap-add NET_RAW \
    -v /path/to/config.toml:/etc/reflector/config.toml:ro \
    ghcr.io/sbogomolov/reflector:latest
```

To keep it running as a service, drop `--rm` and run it detached with a restart policy:

```sh
docker run -d --name reflector --restart unless-stopped \
    --network host \
    --cap-drop ALL --cap-add NET_RAW \
    -v /path/to/config.toml:/etc/reflector/config.toml:ro \
    ghcr.io/sbogomolov/reflector:latest
```

Logs are timestamped in UTC by default; pass `-e TZ=Europe/Berlin` (any zoneinfo name) for local time — the zoneinfo database is bundled in the image.

#### On MikroTik RouterOS

The `arm64`, `arm/v7`, and `arm/v5` variants let the reflector run on the router itself through the RouterOS *Container* feature, bridging two of the router's VLANs without a separate host. Since it has to see both segments, give the container **two `veth` interfaces, one bridged into each VLAN**, and name them as the entry's `source_if` / `target_if`:

```toml
[livingroom-tv]
source_if = "veth-lan"   # veth bridged into the LAN VLAN
target_if = "veth-iot"   # veth bridged into the IoT VLAN
mac       = "B0:37:95:C5:60:BE"   # optional; target a specific device (omit for the whole VLAN)
wol       = true         # enable Wake-on-LAN, disabled by default
mdns      = true         # enable mDNS, disabled by default
ssdp      = true         # enable SSDP, disabled by default
dial      = true         # enable the DIAL proxy, disabled by default
```

Mount the config to `/etc/reflector/config.toml`. For the RouterOS side — enabling container mode, creating the `veth`s, and attaching each to its VLAN — see MikroTik's [Container documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container).

## Configuration

`config.toml` contains optional top-level settings plus at least one reflector entry. An entry is a named table — its name is the label used in logs — describing one `source_if` → `target_if` bridge that enables any combination of the three protocols. `log_level` is the only top-level setting:

```toml
log_level = "info"               # optional; one of debug | info | warning | error (default: info)

[tv]
source_if = "en0"                # required; interface to listen on (must differ from target_if)
target_if = "lo0"                # required; interface to emit reflected traffic on
mac       = "B0:37:95:C5:60:BE"  # optional; the device's MAC (see below). Omit for a whole network.
wol       = true                 # optional; enable Wake-on-LAN reflection (default false)
mdns      = true                 # optional; enable mDNS reflection (default false)
ssdp      = true                 # optional; enable SSDP reflection (default false)
dial      = true                 # optional; enable the DIAL app proxy (requires ssdp; IPv4-only; default false)
wol_ports = [7, 9]               # optional; WoL UDP ports (default [7, 9]); only valid when wol = true
address_family = "default"       # optional; default | dual | ipv4 | ipv6 (default "default")
```

An entry must enable at least one protocol and expands into one reflector per enabled protocol, all sharing the entry's interfaces, `mac`, and `address_family`. The same shape serves a single device (set `mac`) or a whole network (omit `mac`). No IP addresses ever appear in the config. `dial` is not a separate reflector — it augments the entry's SSDP reflector with the DIAL application proxy (so it requires `ssdp`; see [DIAL](#dial)).

### The `mac` field

`mac` is optional and, when set, names a single device — coherently across all three protocols, because a device's NIC MAC is both the target of its Wake-on-LAN magic packet and the L2 source of its mDNS/SSDP advertisements:

- **WoL** re-emits only magic packets whose payload targets `mac`.
- **mDNS / SSDP** relay, in the target→source direction, only frames whose L2 source MAC is `mac` (exposing just that device); the source→target direction is never MAC-filtered. For SSDP the same filter scopes the proxied unicast `200 OK` replies — only `mac`'s responses are carried back to a searcher.

Omit `mac` for a network-level entry: WoL proxies every valid magic packet, and mDNS/SSDP reflect all traffic in both directions.

### `address_family`

`"default"` attempts both IPv4 and IPv6, requires IPv4, and treats IPv6 as best-effort; `"dual"` requires both; `"ipv4"` / `"ipv6"` use only one. It applies to every protocol the entry enables. mDNS and SSDP are bidirectional, so a handled family must have a source address on **both** interfaces (the target re-emits relayed queries/searches, the source re-emits relayed responses/advertisements). This condition is re-checked continuously at runtime (see [Reacting to address changes](#reacting-to-address-changes) below): a family is torn down if either interface loses its address and brought back up once both can send it again.

### Reacting to address changes

The reflector watches the kernel for interface address changes (a `NETLINK_ROUTE` socket on Linux, a `PF_ROUTE` socket on macOS) and adapts at runtime, without a restart. mDNS and SSDP bring a family up — joining its multicast group(s) and installing its capture registrations — once that family becomes reflectable (a source address for it is present on **both** interfaces), and tear it down when either interface loses the address; the family resumes automatically when the address returns. WoL keeps its captures installed and instead checks reachability per packet, so it has nothing to join or leave. Either way, a best-effort IPv6 family that had no address at startup begins reflecting as soon as one appears. Gaining a family logs at `info`; losing a *required* family logs at `error`, an optional one at `info`. The monitor is best-effort: if it cannot start, the reflector logs a warning and runs without address refresh.

### Per-protocol behavior

| Protocol | Port(s) | Group / destination | Relay direction |
|---|---|---|---|
| WoL | `wol_ports` (default 7, 9) | `255.255.255.255` (v4) / `ff02::1` (v6) | magic packets source → target |
| mDNS | 5353 | `224.0.0.251` / `ff02::fb` | queries source→target, responses target→source |
| SSDP | 1900 | `239.255.255.250` / `ff02::c` + `ff05::c` | M-SEARCH source→target, NOTIFY target→source |
| DIAL | 1900 + ephemeral TCP | (uses SSDP discovery) | terminating HTTP reverse proxy (IPv4 only) |

WoL matching requires the magic-packet sequence (six `0xFF` bytes followed by the target MAC repeated 16 times) at the start of the UDP payload; trailing bytes such as a SecureOn password are ignored when matching and forwarded as-is. mDNS responses include unsolicited announcements (so they flow target→source too); mDNS/SSDP datagrams are re-emitted verbatim to the same group (SSDP at hop limit 2).

For SSDP, multicast reflection delivers **passive** discovery — devices' periodic `NOTIFY ssdp:alive` advertisements reach the source segment so clients see them. **Active** discovery works end to end as well: a client's `M-SEARCH` is relayed to the target segment from a reserved ephemeral port, and the device's unicast `HTTP/1.1 200 OK` reply to that port is proxied back across to the original searcher. The proxy is always on whenever `ssdp` is enabled — it keeps one short-lived session per in-flight search (expiring shortly after the search's `MX` window) and needs no configuration. Reaching a device's `LOCATION` URL and driving an app launch across segments is the job of the optional DIAL proxy below.

### DIAL

DIAL (DIscovery And Launch — the protocol behind "cast to TV" for YouTube, Netflix, etc.) lets a phone or laptop find a smart TV and launch an app on it. The catch: a DIAL device restricts its description and REST endpoints to its **own subnet**, so a client on a different segment discovers the device but cannot drive it. Setting `dial = true` on an SSDP entry makes the reflector bridge that gap.

It is a **terminating HTTP reverse proxy**. When a DIAL `LOCATION` (in a relayed `NOTIFY` or `M-SEARCH` `200 OK`) crosses target→source, the reflector mints a per-device ephemeral TCP listener on `source_if`'s address and rewrites the `LOCATION` authority to point at that listener. A source-side client then connects to the reflector, which opens an upstream connection to the device **bound to `target_if`'s address** — so the device sees an on-subnet client and serves it. Along the way it rewrites the four authority-bearing headers (`LOCATION`, the description's `Application-URL`, request `Host`, and response `Location`) from the device's authority to a reflector authority and back; HTTP bodies stream through untouched. App launch (`POST`) and stop (`DELETE`) work end to end.

`dial = true` requires `ssdp` and is **IPv4-only** (the DIAL spec ties the device authority to an IPv4 address); an `ipv6`-only entry with `dial = true` is rejected at startup. It is the only DIAL knob — every cap and timeout is a fixed constant. The proxy degrades benignly: a `LOCATION`/`Application-URL` the reflector can't rewrite (an `https` URL, a hostname instead of an IPv4 literal, a listener cap/bind failure) is forwarded unchanged and logged, leaving on-subnet discovery unaffected.

### Duplicate detection

Entry names are unique (TOML rejects duplicate table names). Beyond that, two entries that enable the same protocol are rejected as a duplicate of that protocol only when they could reflect the same packet twice: same `source_if`, same `target_if`, overlapping MAC selection, overlapping address-family handling, and — for WoL — at least one shared port. MAC selection overlaps when both entries set the same `mac`, or when either omits `mac` (any device). Address-family handling overlaps when both can handle the same IP version: an `ipv4`-only and an `ipv6`-only entry never overlap, while `default`/`dual` overlap with either. Entries that differ in interface, MAC, address family (or WoL ports), or that enable *different* protocols, coexist.

## Tests

```sh
cmake --build build
ctest --test-dir build --output-on-failure
ctest --test-dir build -L unit --output-on-failure
```

`--output-on-failure` prints the full test log for any failing test (ctest hides output for passing tests by default). Several tests open loopback UDP sockets and exchange real packets, so they need to run outside any sandbox that blocks local networking.

A subset of tests does privileged loopback networking — real packet capture, or binding a UDP sender to the loopback interface — and needs the same privileges the reflector itself does (see [Runtime privileges](#runtime-privileges)). They carry an extra `root` label and probe for the privilege at startup — if it's missing they `GTEST_SKIP` cleanly, so the default `ctest` run is green on an under-privileged box. Select or exclude them explicitly with:

```sh
ctest --test-dir build -L root --output-on-failure         # only the capture-using tests
ctest --test-dir build -LE root --output-on-failure        # skip them outright
```

Two of the `root` tests go further: they **create a virtual interface pair** (`veth` on Linux,
`feth` on macOS) to inject a frame on one interface and observe it on the other, which validates the
raw send path against the real kernel. Creating interfaces needs full root (`CAP_NET_ADMIN`) — more
than the `CAP_NET_RAW` that capture uses, and a `setcap` grant is not enough — so they only run when
invoked with `sudo` (and `GTEST_SKIP` otherwise):

```sh
sudo ctest --test-dir build -L root --output-on-failure
```

### Docker-backed tests

Docker-backed coverage is opt-in because it builds/runs containers and, for e2e, creates temporary Docker networks. Run the Dockerfile unit-test targets with:

```sh
./docker_test.sh                      # Debug (ASan/UBSan)
./docker_test.sh release              # Release
./docker_test.sh valgrind             # unit binary under Valgrind memcheck (Debug, no sanitizers)
./docker_test.sh debug -R RawSocket   # extra args are forwarded to ctest
```

The script builds the test image and runs the suite in a container started with `--cap-add=NET_ADMIN`.
That capability is required because the interface-pair `root` tests create a `veth` pair, and `docker
build` can't grant it — so building and running the tests in one `docker build` step (as the image
used to) silently skips them. `CAP_NET_RAW`, which loopback capture needs, is already in Docker's
default capability set, so only `NET_ADMIN` has to be added.

Run the e2e suite directly with:

```sh
python3 e2e/run.py                # against the production image
python3 e2e/run.py --valgrind     # the reflector under Valgrind memcheck
```

`--valgrind` runs the reflector under memcheck (the `runtime-valgrind` image: the Release binary with `-ggdb3`) and fails the run on any leak, leaked fd, or memcheck error. The e2e runner builds `reflector:e2e` by default, uses `python:3.13-alpine` for UDP probe containers, can print reflector logs with `--show-reflector-logs`, and leaves Docker resources behind on failure when passed `--keep-on-failure`.

To register Docker-backed tests with CTest:

```sh
cmake -S . -B build \
    -DREFLECTOR_ENABLE_E2E_TESTS=ON \
    -DREFLECTOR_ENABLE_DOCKER_TESTS=ON \
    -DREFLECTOR_ENABLE_VALGRIND_UNIT_TESTS=ON \
    -DREFLECTOR_ENABLE_VALGRIND_E2E_TESTS=ON
ctest --test-dir build -L docker --output-on-failure
```

`REFLECTOR_ENABLE_DOCKER_TESTS` adds a `docker`-labeled test that runs `docker_test.sh` (building the Debug or Release test image to match the build and running its unit suite in a container with `CAP_NET_ADMIN`). `REFLECTOR_ENABLE_E2E_TESTS` adds the e2e runner. `REFLECTOR_ENABLE_VALGRIND_UNIT_TESTS` adds `Valgrind.Unit`, which runs the unit binary under Valgrind memcheck (a Debug, no-sanitizer build, since Valgrind and ASan are mutually exclusive); `REFLECTOR_ENABLE_VALGRIND_E2E_TESTS` adds `Valgrind.E2E`, which runs the e2e suite with the reflector under memcheck (the production Release binary built with `-ggdb3` for readable traces). All are labeled `docker`; the e2e tests are also labeled `e2e` and the valgrind tests `valgrind`, so `-L e2e` or `-L valgrind` selects just that coverage.

## License

Copyright 2026 Sergii Bogomolov.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
