# reflector

Reflects Wake-on-LAN magic packets received on one network interface onto another as a directed broadcast. Useful when the host that sends WoL packets and the host you want to wake live on different L2 segments — for example, a router bridging a wired LAN to a Wi-Fi network where directed broadcasts are not forwarded.

## Platform support

Linux and macOS. Tested on macOS; Linux build is gated on the toolchain checks below but has not been exercised in CI yet.

## Build

Prerequisites:

- CMake ≥ 3.14, Ninja
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

Dependencies (`tomlplusplus`, `googletest`) are fetched via `FetchContent` — no system packages required.

## Run

```sh
./build/reflector [config.toml]
```

The default config path is `./config.toml`. The process logs to stdout and shuts down cleanly on `SIGINT` / `SIGTERM`.

### Linux capabilities

Binding a UDP socket to a specific interface uses `SO_BINDTODEVICE`, which requires `CAP_NET_RAW`. Either run as root, or grant the capability once:

```sh
sudo setcap cap_net_raw=eip ./build/reflector
```

macOS uses `IP_BOUND_IF`, which has no equivalent privilege requirement.

## Configuration

`config.toml` contains one or more `[[wol]]` entries:

```toml
[[wol]]
name      = "tv"               # human-readable label, used in logs
mac       = "B0:37:95:C5:60:BE" # MAC address of the host to wake
source_if = "en0"              # interface to listen on (must differ from target_if)
target_if = "lo0"              # interface to broadcast on
ports     = [7, 9]             # optional; defaults to [7, 9] (the standard WoL ports)
```

Each entry installs a listener on `source_if` for the listed UDP ports, matches incoming packets against the WoL magic-packet format for `mac`, and rebroadcasts matching packets to `255.255.255.255` on `target_if` on the same destination port.

## Tests

```sh
cmake --build build
ctest --test-dir build --output-on-failure
```

`--output-on-failure` prints the full test log for any failing test (ctest hides output for passing tests by default). Several tests open loopback UDP sockets and exchange real packets, so they need to run outside any sandbox that blocks local networking.

## License

Copyright 2026 Sergii Bogomolov.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
