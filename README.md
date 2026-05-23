# reflector

Reflects Wake-on-LAN magic packets received on one network interface onto another. Useful when the host that sends WoL packets and the host you want to wake live on different L2 segments — for example, a router bridging a wired LAN to a Wi-Fi network where broadcasts are not forwarded.

By default, each reflector entry requires IPv4 handling and attempts IPv6 on a best-effort basis. Magic packets received over IPv4 are re-emitted as the IPv4 limited broadcast (`255.255.255.255`); packets received over IPv6 are re-emitted to the IPv6 link-local all-nodes multicast group (`ff02::1`). If IPv4 cannot be initialized for an entry, startup fails. If only IPv6 cannot be initialized, IPv4 keeps running.

## Platform support

Linux and macOS. The CI workflow runs the unit suite on Ubuntu 24.04 x64, Ubuntu 24.04 arm64, and macOS 15; it also runs Docker build and e2e jobs on Ubuntu 24.04.

## Build

Prerequisites:

- CMake ≥ 3.22, Ninja, Git
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

The runtime image uses pinned Debian/distroless base image digests. By default, `./docker_build.sh` loads a single-platform image into the local Docker engine and tags it as `reflector:<version>` and `reflector:latest`. With `--push`, it publishes `ghcr.io/sbogomolov/reflector` as a multi-platform manifest for `linux/amd64` and `linux/arm64`; override the destination with `--image`, or override architectures with `--platforms` for unusual deployment targets.

## Release

Release checklist:

- Make sure `CMakeLists.txt` has the new project version.
- Make sure all changes for the release are present on `origin/main`.
- Check that all CI jobs on `origin/main` succeeded.
- Create a GitHub release with the tag corresponding to the new version, for example `v0.1.4`.
- Push the new Docker images with `./docker_build.sh --push`.

## Run

```sh
./build/reflector [config.toml]
```

The default config path is `./config.toml`. The process logs to stdout and shuts down cleanly on `SIGINT` / `SIGTERM`.

### Runtime privileges

The reflector opens an L2 packet-capture socket on each `source_if` to observe incoming
WoL traffic, and a UDP sender bound to each `target_if` to re-emit it. The capture
socket is what drives the privilege requirements below; the sender does not need to
bind to a port (it sends only), so no WoL-port-related privileges are required even
when the default ports `7` / `9` are in use.

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

## Configuration

`config.toml` contains optional top-level settings plus at least one `[[wol]]`
entry:

```toml
log_level = "info"             # optional; one of debug | info | warning | error (default: info)

[[wol]]
name      = "tv"                # human-readable label, used in logs
mac       = "B0:37:95:C5:60:BE" # optional; when omitted, all WoL magic packets are proxied
source_if = "en0"               # interface to listen on (must differ from target_if)
target_if = "lo0"               # interface to emit reflected packets on
ports     = [7, 9]              # optional; defaults to [7, 9] (the standard WoL ports)
address_family = "default"      # optional; default | dual | ipv4 | ipv6
```

Each entry installs listeners on `source_if` for the listed UDP ports, matches incoming packets against the WoL magic-packet format for `mac` when configured, and re-emits matching packets on `target_if` on the same destination port. Matching requires the magic-packet sequence (six `0xFF` bytes followed by the target MAC repeated 16 times) to begin at the start of the UDP payload; trailing bytes, such as a SecureOn password, are ignored when matching and forwarded as-is. If `mac` is omitted, every valid WoL magic packet is re-emitted. IPv4 packets go to `255.255.255.255`; IPv6 packets go to `ff02::1`. No IP addresses appear in the config.

`address_family = "default"` attempts both IPv4 and IPv6, requires IPv4, and treats IPv6 as best-effort. Use `"dual"` to require both address families, or `"ipv4"` / `"ipv6"` to use only one.

Every WoL entry name must be unique. Beyond the name, duplicate detection rejects only rules that could reflect the same packet twice: the entries must use the same `source_if`, the same `target_if`, at least one common UDP port, overlapping MAC selection, and overlapping address-family handling. MAC selection overlaps when both entries use the same `mac`, or when either entry omits `mac` and therefore accepts any MAC. Address-family handling overlaps when the two entries can both handle the same IP version — an `ipv4`-only rule and an `ipv6`-only rule never overlap, while `default`/`dual` handle both versions and so overlap with either. Rules with different source interfaces, target interfaces, disjoint port sets, or non-overlapping address families can coexist.

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

Docker-backed coverage is opt-in because it builds/runs containers and, for e2e, creates temporary Docker networks. Run the Dockerfile unit-test targets directly with:

```sh
docker build --target test-debug .
docker build --target test-release .
```

The interface-pair tests skip during these builds: the `docker build` sandbox grants `CAP_NET_RAW`
(so the loopback `root` tests run) but not `CAP_NET_ADMIN`, which creating `veth` needs. To exercise
them in a container, tag the image and re-run ctest from a container started with that capability:

```sh
docker build --target test-debug -t reflector-test .
docker run --rm --cap-add NET_ADMIN reflector-test \
    ctest --test-dir build-test-debug -L root --output-on-failure
```

Run the e2e suite directly with:

```sh
python3 e2e/run.py
```

The e2e runner builds `reflector:e2e` by default, uses `python:3.13-alpine` for UDP probe containers, can print reflector logs with `--show-reflector-logs`, and leaves Docker resources behind on failure when passed `--keep-on-failure`.

To register Docker-backed tests with CTest:

```sh
cmake -S . -B build \
    -DREFLECTOR_ENABLE_E2E_TESTS=ON \
    -DREFLECTOR_ENABLE_DOCKER_TESTS=ON
ctest --test-dir build -L docker --output-on-failure
```

`REFLECTOR_ENABLE_DOCKER_TESTS` adds the Dockerfile unit-test target (`test-debug` for Debug builds, `test-release` otherwise). `REFLECTOR_ENABLE_E2E_TESTS` adds the e2e runner. Both are labeled `docker`; the e2e test is also labeled `e2e`, so `-L e2e` selects only e2e coverage.

## License

Copyright 2026 Sergii Bogomolov.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
